#include "x86_d3d9.h"

#include <algorithm>
#include <array>
#include <sys/mman.h>

namespace raven {

namespace {

struct Method {
	std::string_view interface, name;
	uint32_t index, words;
};

constexpr Method methods[] = {
#include "x86_d3d9_vtables.inc"
};

const std::map<std::string, uint32_t> &words_by_name()
{
	static const auto table = [] {
		std::map<std::string, uint32_t> result;
		for (const auto &method : methods)
			result.emplace(std::string(method.interface) + "." + std::string(method.name), method.words);
		return result;
	}();
	return table;
}

void write_word(NativeProcess &process, uint64_t address, uint32_t value)
{
	const uint8_t bytes[4] = {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)};
	process.write_memory(address, bytes);
}

uint32_t read_word(NativeProcess &process, uint64_t address)
{
	const auto bytes = process.read_memory(address, 4);
	return uint32_t(bytes[0]) | uint32_t(bytes[1]) << 8 | uint32_t(bytes[2]) << 16 | uint32_t(bytes[3]) << 24;
}

constexpr uint32_t e_notimpl = 0x80004001U;

}

NativeX86D3D9::NativeX86D3D9(NativeProcess &process, NativeEnvironment &environment) : process(process), environment(environment) {}

std::vector<std::string_view> NativeX86D3D9::method_names()
{
	static std::vector<std::string> storage;
	if (storage.empty())
		for (const auto &[name, words] : words_by_name())
			storage.push_back(name);
	return {storage.begin(), storage.end()};
}

uint32_t NativeX86D3D9::method_words(std::string_view name)
{
	const auto found = words_by_name().find(std::string(name));
	return found == words_by_name().end() ? 0 : found->second;
}

std::span<const std::string_view> NativeX86D3D9::entry_names()
{
	static constexpr std::array<std::string_view, 1> names{"Direct3DCreate9"};
	return names;
}

uint64_t NativeX86D3D9::vtable(const std::string &interface)
{
	const auto known = vtables.find(interface);
	if (known != vtables.end())
		return known->second;
	std::vector<std::pair<uint32_t, std::string>> entries;
	for (const auto &method : methods)
		if (method.interface == interface)
			entries.emplace_back(method.index, std::string(method.interface) + "." + std::string(method.name));
	if (entries.empty())
		throw std::runtime_error("native Direct3D 9 has no interface " + interface);
	const auto base = process.map_memory(4096, PROT_READ | PROT_WRITE);
	for (const auto &[index, name] : entries) {
		const auto trap = trap_addresses.find(name);
		if (trap == trap_addresses.end())
			throw std::runtime_error("native Direct3D 9 method has no trap: " + name);
		write_word(process, base + index * 4ULL, uint32_t(trap->second));
	}
	vtables[interface] = base;
	return base;
}

// An object is three words: the vtable, the reference count, and room for the implementation.
uint64_t NativeX86D3D9::make_object(const std::string &interface)
{
	const auto object = process.map_memory(4096, PROT_READ | PROT_WRITE);
	write_word(process, object, uint32_t(vtable(interface)));
	write_word(process, object + 4, 1);
	interfaces[object] = interface;
	return object;
}

bool NativeX86D3D9::dispatch(std::string_view name)
{
	if (name == "Direct3DCreate9") {
		process.api_arguments(1);
		process.return_api(make_object("IDirect3D9"));
		return true;
	}
	if (!words_by_name().contains(std::string(name)))
		return false;
	const auto words = method_words(name);
	const auto args = process.api_arguments(words);
	const auto separator = name.find('.');
	const auto method = name.substr(separator + 1);
	if (method == "AddRef" || method == "Release") {
		const auto count = read_word(process, args[0] + 4) + (method == "AddRef" ? 1 : uint32_t(-1));
		write_word(process, args[0] + 4, count);
		process.return_api(count);
	} else if (method == "QueryInterface") {
		process.write_memory(args[2], std::vector<uint8_t>(4));
		process.return_api(0x80004002U);
	} else if (name == "IDirect3D9.CreateDevice") {
		write_word(process, args[6], uint32_t(make_object("IDirect3DDevice9")));
		process.return_api(0);
	} else {
		// Behaviour comes method by method; until then a call is reported through the API trace and answers "not implemented".
		process.return_api(e_notimpl);
	}
	return true;
}

}

#include "x86_d3d9.h"

#include <array>

namespace raven {

namespace {

constexpr ComMethod methods[] = {
#include "x86_d3d9_vtables.inc"
};

constexpr uint32_t e_notimpl = 0x80004001U;

}

NativeX86D3D9::NativeX86D3D9(NativeProcess &process) : process(process), com_(process, methods) {}

std::vector<std::string_view> NativeX86D3D9::method_names()
{
	return com_names(methods);
}

uint32_t NativeX86D3D9::method_words(std::string_view name)
{
	return com_words(methods, name);
}

std::span<const std::string_view> NativeX86D3D9::entry_names()
{
	static constexpr std::array<std::string_view, 1> names{"Direct3DCreate9"};
	return names;
}

bool NativeX86D3D9::dispatch(std::string_view name)
{
	if (name == "Direct3DCreate9") {
		process.api_arguments(1);
		process.return_api(com_.make_object("IDirect3D9"));
		return true;
	}
	if (!com_.owns(name))
		return false;
	const auto args = process.api_arguments(com_.words(name));
	const auto [interface, method] = com_.split(name);
	if (com_.counted(method, args))
		return true;
	if (method == "QueryInterface") {
		process.write_memory(args[2], std::vector<uint8_t>(4));
		process.return_api(0x80004002U);
	} else if (name == "IDirect3D9.CreateDevice") {
		com_.write32(args[6], uint32_t(com_.make_object("IDirect3DDevice9")));
		process.return_api(0);
	} else {
		// Behaviour comes method by method; until then a call is reported through the API trace and answers "not implemented".
		process.return_api(e_notimpl);
	}
	return true;
}

}

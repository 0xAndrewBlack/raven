#include "heap.h"

#include <array>
#include <algorithm>
#include <stdexcept>

namespace raven {

NativeHeap::NativeHeap(NativeProcess &process, NativeEnvironment &environment, ModuleSet &modules, const PEImage &entry)
	: process(process), environment(environment), modules(modules), entry(entry) {}

std::span<const std::string_view> NativeHeap::nt_exports()
{
	static constexpr std::array<std::string_view,6> names{
		"RtlAllocateHeap","RtlCreateHeap","RtlDestroyHeap","RtlFreeHeap","RtlReAllocateHeap","RtlSizeHeap"};
	return names;
}

uint64_t NativeHeap::call(std::string_view name, std::span<const uint64_t> arguments)
{
	const auto address=modules.resolve({"raven-rtl.dll",std::string(name),0,false,0});
	const auto result=invoke(address,arguments);
	if (result.stop!=NativeStop::returned) throw result;
	return result.value;
}

void NativeHeap::initialize(std::function<NativeResult(uint64_t,std::span<const uint64_t>)> caller)
{
	if (!modules.all().contains("raven-rtl.dll")) return;
	const auto &module=*modules.all().at("raven-rtl.dll");
	if (invoke || !(module.image.characteristics & 0x2000) || module.image.entry ||
		module.image.directories[9].address || module.image.directories[9].size || !caller)
		throw std::runtime_error("native RTL component requires explicit initialization without DllMain or TLS");
	for (const auto name : {"RavenInitializeRTL","RtlCreateHeap","RtlAllocateHeap","RtlReAllocateHeap",
		"RtlFreeHeap","RtlSizeHeap","RtlDestroyHeap"}) {
		const auto found=std::find_if(module.exports.begin(),module.exports.end(),[&](const auto &symbol) {
			return std::find(symbol.names.begin(),symbol.names.end(),name)!=symbol.names.end();
		});
		if (found==module.exports.end() || !found->address || !found->forwarder.empty())
			throw std::runtime_error("native RTL component requires its own heap implementation exports");
	}
	invoke=std::move(caller);
	const uint64_t initialization[]{environment.prepare_heaps(),NativeEnvironment::heap_capacity};
	if (call("RavenInitializeRTL",initialization))
		throw std::runtime_error("native RTL initialization failed");
	const uint64_t creation[]{2,0,entry.heap_reserve,entry.heap_commit,0,0};
	environment.publish_process_heap(call("RtlCreateHeap",creation));
}

bool NativeHeap::dispatch(std::string_view name)
{
	if (!invoke) return false;
	if (name=="GetProcessHeap") {
		process.api_arguments(0);
		process.return_api(environment.process_heap());
		return true;
	}
	const bool nt=name.starts_with("Rtl");
	std::string_view function;
	size_t count=0;
	if (name=="HeapCreate" || name=="RtlCreateHeap") { function="RtlCreateHeap"; count=nt ? 6 : 3; }
	else if (name=="HeapDestroy" || name=="RtlDestroyHeap") { function="RtlDestroyHeap"; count=1; }
	else if (name=="HeapAlloc" || name=="RtlAllocateHeap") { function="RtlAllocateHeap"; count=3; }
	else if (name=="HeapReAlloc" || name=="RtlReAllocateHeap") { function="RtlReAllocateHeap"; count=4; }
	else if (name=="HeapFree" || name=="RtlFreeHeap") { function="RtlFreeHeap"; count=3; }
	else if (name=="HeapSize" || name=="RtlSizeHeap") { function="RtlSizeHeap"; count=3; }
	else return false;
	const auto arguments=process.api_arguments(count);
	const auto previous=environment.last_error();
	uint64_t result=0;
	if (!nt && function!="RtlCreateHeap" && function!="RtlDestroyHeap") {
		const uint32_t mask=function=="RtlAllocateHeap" ? 13 : function=="RtlReAllocateHeap" ? 29 : 1;
		if (uint32_t(arguments[1]) & ~mask) {
			environment.set_last_error(120); process.return_api(function=="RtlSizeHeap" ? UINT64_MAX : 0); return true;
		}
	}
	if (!nt && function=="RtlCreateHeap") {
		if (uint32_t(arguments[0]) & ~5U) {
			environment.set_last_error(120); process.return_api(0); return true;
		}
		const uint64_t creation[]{uint32_t(arguments[0]) | (arguments[2] ? 0U : 2U),0,arguments[2],arguments[1],0,0};
		result=call(function,creation);
	} else result=call(function,arguments);
	if (function=="RtlFreeHeap") result=uint8_t(result);
	if (!nt) {
		const bool failed=function=="RtlDestroyHeap" ? result!=0 : function=="RtlSizeHeap" ? result==UINT64_MAX : result==0;
		if (failed) environment.set_last_error(function=="RtlAllocateHeap" || function=="RtlReAllocateHeap" || function=="RtlCreateHeap" ? 8 : 87);
		else environment.set_last_error(previous);
		if (function=="RtlDestroyHeap") result=result ? 0 : 1;
	}
	process.return_api(result);
	return true;
}

}

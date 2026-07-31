#include "exceptions.h"

#include <stdexcept>

namespace raven {

NativeResult native_raise_exception(NativeProcess &process)
{
	const auto arguments = process.api_arguments(4);
	NativeResult result{NativeStop::exception, static_cast<uint32_t>(arguments[0]),
		process.context().registers.rip - 1, 0};
	result.exception_flags = static_cast<uint32_t>(arguments[1]);
	if (arguments[3]) {
		const auto count = static_cast<uint32_t>(arguments[2]);
		if (count > 15)
			throw std::runtime_error("RaiseException exceeds the Windows parameter limit");
		if (!count)
			return result;
		const auto bytes = process.read_memory(arguments[3], size_t(count) * 8);
		result.exception_information.resize(count);
		for (size_t index = 0; index < bytes.size(); ++index)
			result.exception_information[index / 8] |= uint64_t(bytes[index]) << ((index % 8) * 8);
	}
	return result;
}

NativeResult native_raise_rtl_exception(NativeProcess &process, bool status_only)
{
	const auto arguments=process.api_arguments(1);
	NativeResult result{NativeStop::exception,uint32_t(arguments[0]),process.context().registers.rip-1,0};
	if (status_only) { result.exception_flags=1; return result; }
	const auto bytes=process.read_memory(arguments[0],152);
	const auto field=[&](size_t offset,size_t size) {
		uint64_t value=0;
		for (size_t byte=0; byte<size; ++byte) value|=uint64_t(bytes[offset+byte])<<(byte*8);
		return value;
	};
	result.value=field(0,4);
	result.exception_flags=uint32_t(field(4,4));
	result.instruction=field(16,8);
	const auto count=field(24,4);
	if (count>15) throw std::runtime_error("RtlRaiseException exceeds the Windows parameter limit");
	for (size_t index=0; index<count; ++index) result.exception_information.push_back(field(32+index*8,8));
	return result;
}

}

#pragma once

#include "api.h"

#include <stdexcept>

namespace raven {

// An argument that callers adapting older entry points may leave out.
inline uint64_t optional_argument(const ApiCall &call, size_t index)
{
	try {
		return call[index];
	} catch (const std::out_of_range &) {
		return 0;
	}
}

// SECURITY_ATTRIBUTES: the length, the descriptor pointer and then bInheritHandle, whose place depends on the pointer width.
inline bool inheritable_handle(const ApiCall &call, uint64_t attributes)
{
	return attributes && call.load<uint32_t>(attributes + (call.pointer_width() == 8 ? 16 : 8)) != 0;
}

}

#pragma once

#include "environment.h"
#include "objects.h"

namespace raven {

class NativeObjectAPI {
public:
	NativeObjectAPI(NativeProcess &process, NativeEnvironment &environment, NativeObjects &objects,
		std::chrono::steady_clock::time_point deadline);
	bool dispatch(std::string_view name);
	static std::span<const std::string_view> nt_exports();

private:
	NativeProcess &process;
	NativeEnvironment &environment;
	NativeObjects &objects;
	std::chrono::steady_clock::time_point deadline;
	bool file_io(std::string_view name);
};

}

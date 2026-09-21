#include "x86_thread_api.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <sys/mman.h>

namespace raven {

namespace {

constexpr std::array<std::pair<std::string_view, uint32_t>, 15> thread_exports{{
	{"CreateThread", 6}, {"DeleteCriticalSection", 1}, {"EnterCriticalSection", 1}, {"ExitThread", 1}, {"GetExitCodeThread", 2},
	{"InitializeCriticalSection", 1}, {"InitializeCriticalSectionAndSpinCount", 2}, {"InitializeCriticalSectionEx", 3}, {"LeaveCriticalSection", 1}, {"ResumeThread", 1}, {"SetThreadPriority", 2},
	{"Sleep", 1}, {"SwitchToThread", 0}, {"TryEnterCriticalSection", 1}, {"WaitForSingleObject", 2},
}};

constexpr uint32_t wait_timeout = 0x102, wait_failed = UINT32_MAX, still_active = 259;

}

NativeX86Threads::NativeX86Threads(NativeProcess &process, NativeEnvironment &environment, NativeObjects &objects, NativeThreads &threads)
	: process(process), environment(environment), objects(objects), threads(threads)
{
}

std::span<const std::pair<std::string_view, uint32_t>> NativeX86Threads::exports()
{
	return thread_exports;
}

uint32_t NativeX86Threads::wait(uint64_t handle, uint32_t milliseconds)
{
	const uint32_t id = threads.current_id();
	std::optional<std::chrono::steady_clock::time_point> wake;
	if (milliseconds != UINT32_MAX)
		wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
	for (;;) {
		const int state = objects.signaled(handle, id);
		if (state < 0) {
			environment.set_last_error(6);
			return wait_failed;
		}
		if (state == 1) {
			objects.consume(handle, id);
			return 0;
		}
		if (milliseconds == 0 || (wake && std::chrono::steady_clock::now() >= *wake))
			return wait_timeout;
		threads.block([&] { return objects.signaled(handle, id) == 1; }, wake);
	}
}

bool NativeX86Threads::dispatch(std::string_view name)
{
	const auto known = std::find_if(thread_exports.begin(), thread_exports.end(), [&](const auto &item) { return item.first == name; });
	if (known == thread_exports.end())
		return false;
	const auto args = process.api_arguments(known->second);
	if (name == "CreateThread") {
		const uint32_t flags = uint32_t(args[4]);
		if (args[0] || (flags & ~uint32_t(0x4 | 0x10000))) {
			environment.set_last_error(87);
			process.return_api(0);
			return true;
		}
		std::shared_ptr<GuestThread> thread;
		try {
			thread = threads.create(args[2], args[3], args[1] ? args[1] : 1024 * 1024, flags & 4);
		} catch (const std::runtime_error &) {
			environment.set_last_error(8);
			process.return_api(0);
			return true;
		}
		auto object = std::make_shared<ThreadObject>(thread);
		const auto made = objects.add_object(object);
		if (made.status) {
			threads.terminate(thread, 0);
			environment.set_last_error(8);
			process.return_api(0);
			return true;
		}
		if (args[5]) {
			const uint32_t id = thread->id;
			process.write_memory(args[5], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&id), 4));
		}
		process.return_api(made.value);
	} else if (name == "ExitThread") {
		threads.exit_current(uint32_t(args[0]));
	} else if (name == "GetExitCodeThread") {
		// A thread of another process reports through the pipe its process writes the exit code to.
		if (const auto remote = objects.object_as<RemoteThreadObject>(args[0])) {
			const uint32_t code = remote->code().value_or(still_active);
			process.write_memory(args[1], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&code), 4));
			process.return_api(1);
			return true;
		}
		// The handle table says what the handle is now: a value can be reused after the thread it named was closed.
		const auto object = objects.object_as<ThreadObject>(args[0]);
		if (!object) {
			environment.set_last_error(6);
			process.return_api(0);
			return true;
		}
		const auto &thread = *object->thread;
		const uint32_t code = thread.state == GuestThread::State::done ? thread.exit_code : still_active;
		process.write_memory(args[1], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&code), 4));
		process.return_api(1);
	} else if (name == "ResumeThread") {
		const auto object = objects.object_as<ThreadObject>(args[0]);
		if (!object) {
			environment.set_last_error(6);
			process.return_api(UINT32_MAX);
			return true;
		}
		const auto previous = object->thread->suspend_count;
		threads.resume(*object->thread);
		process.return_api(uint32_t(previous));
	} else if (name == "SetThreadPriority") {
		const auto object = objects.object_as<ThreadObject>(args[0]);
		if (object)
			object->thread->priority = int32_t(args[1]);
		process.return_api(object != nullptr);
	} else if (name == "Sleep") {
		const uint32_t milliseconds = uint32_t(args[0]);
		if (!milliseconds) {
			threads.yield();
		} else {
			std::optional<std::chrono::steady_clock::time_point> wake;
			if (milliseconds != UINT32_MAX)
				wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
			threads.block([] { return false; }, wake);
		}
		process.return_api(0);
	} else if (name == "InitializeCriticalSection" || name == "DeleteCriticalSection") {
		sections.erase(args[0]);
		process.return_api(0);
	} else if (name == "InitializeCriticalSectionAndSpinCount" || name == "InitializeCriticalSectionEx") {
		// Spinning is a hint and the flags only tune allocation: the section is the same, and these forms report success. Programs that
		// force debug data find it at DebugInfo, the first word.
		if (name == "InitializeCriticalSectionEx" && (uint32_t(args[2]) & ~0x1f000000U)) {
			environment.set_last_error(87);
			process.return_api(0);
			return true;
		}
		sections.erase(args[0]);
		if (!section_debug)
			section_debug = process.map_memory(4096, PROT_READ | PROT_WRITE);
		const uint32_t debug = uint32_t(section_debug);
		process.write_memory(args[0], std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(&debug), 4));
		process.return_api(1);
	} else if (name == "EnterCriticalSection" || name == "TryEnterCriticalSection") {
		const uint32_t id = threads.current_id();
		auto &section = sections[args[0]];
		const bool free = section.owner == 0 || section.owner == id;
		if (!free && name == "TryEnterCriticalSection") {
			process.return_api(0);
			return true;
		}
		if (!free)
			threads.block([&section, id] { return section.owner == 0 || section.owner == id; }, std::nullopt);
		section.owner = id;
		++section.depth;
		process.return_api(1);
	} else if (name == "LeaveCriticalSection") {
		auto &section = sections[args[0]];
		if (section.depth > 0 && --section.depth == 0)
			section.owner = 0;
		process.return_api(0);
	} else if (name == "SwitchToThread") {
		process.return_api(threads.yield());
	} else {
		process.return_api(wait(args[0], uint32_t(args[1])));
	}
	return true;
}

}

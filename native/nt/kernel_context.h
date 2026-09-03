#pragma once

#include "api.h"
#include "guest_allocator.h"
#include "memory.h"
#include "objects.h"
#include "paths.h"
#include "completion_port.h"
#include "pipe.h"
#include "threads.h"
#include <string>
#include "pe/module_set.h"

namespace raven {

// Thrown by a host handler that moved the guest to another place; the call loop at the named nesting level resumes it.
struct ExecutionRedirected {
	size_t level;
};

// Raised to end the process from deep inside a handler; the call loop turns it into the process result.
struct ProcessExit {
	uint32_t code;
	uint64_t instruction;
};

// Process-wide services that the native kernel32 handlers share; every member outlives the handlers.
struct KernelContext {
	NativeProcess &process;
	NativeEnvironment &environment;
	NativeMemory &memory;
	GuestAllocator &allocator;
	NativeObjects &objects;
	NativeThreads &threads;
	NativePaths &paths;
	ModuleSet &modules;
	const PEModule &entry;
	const NativeLaunch &launch;
	// Runs a guest function to completion (callbacks, thread start routines); stops propagate as exceptions.
	std::function<NativeResult(uint64_t, std::span<const uint64_t>)> call;
	// Top-level exception filter installed by the program (SetUnhandledExceptionFilter).
	uint64_t unhandled_filter = 0;
	// Delivers a CPU fault to the guest's handlers; never returns normally (it redirects or ends the process).
	std::function<void(const NativeResult &)> raise_fault;
	// Walks the guest stack with the unwind tables and names each caller as module+offset (diagnostics only).
	std::function<std::string()> describe_stack;
	// True when the window system has input, paint or timer work for the calling thread (MsgWaitForMultipleObjects).
	std::function<bool()> message_ready;
	// The environment variables the program has now, as the block a new process receives (set by the system handlers).
	std::function<std::u16string()> environment_block;
	// Started operations that finish later, such as overlapped socket transfers.
	std::shared_ptr<Reactor> reactor = std::make_shared<Reactor>();
	// Named pipes served by this process and the pipe operations that have not finished.
	std::shared_ptr<PipeState> pipes = std::make_shared<PipeState>();
};

// Windows FILETIME ticks are 100 ns units since 1601-01-01.
inline constexpr uint64_t filetime_epoch_offset = 11644473600ULL * 10000000ULL;

void register_exception_api(ApiRegistry &registry, KernelContext &context, class NativeUnwinder &unwinder);
class NativeRegistry;
void register_registry_api(ApiRegistry &registry, KernelContext &context, NativeRegistry &hive);
void register_platform_api(ApiRegistry &registry, KernelContext &context);
void register_shell_api(ApiRegistry &registry, KernelContext &context);
void register_version_api(ApiRegistry &registry, KernelContext &context);
void register_shlwapi_api(ApiRegistry &registry, KernelContext &context);
void register_file_api(ApiRegistry &registry, KernelContext &context);
void register_system_api(ApiRegistry &registry, KernelContext &context);
void register_sync_api(ApiRegistry &registry, KernelContext &context);
void register_thread_api(ApiRegistry &registry, KernelContext &context);
void register_memory_api(ApiRegistry &registry, KernelContext &context);
void register_text_api(ApiRegistry &registry, KernelContext &context);
void register_process_api(ApiRegistry &registry, KernelContext &context);
void register_security_api(ApiRegistry &registry, KernelContext &context);
void register_child_process_api(ApiRegistry &registry, KernelContext &context);
void register_winsock_api(ApiRegistry &registry, KernelContext &context);
void register_host_api(ApiRegistry &registry, KernelContext &context);
void register_job_api(ApiRegistry &registry, KernelContext &context);
void register_process_info_api(ApiRegistry &registry, KernelContext &context);
void register_crypt32_api(ApiRegistry &registry, KernelContext &context);
void register_font_service(ApiRegistry &registry, KernelContext &context);
// Starts the program an application name or command line names, looked up the way Windows does; null with the Windows error otherwise.
std::shared_ptr<class ProcessObject> start_program(KernelContext &context, const std::u16string &application, const std::u16string &line,
	const std::u16string &directory, const int (&standard)[3], const std::u16string &environment, int *gate, uint32_t &error,
	std::vector<InheritedHandle> inherited = {});
// Puts a child process into a job; false with the Windows error otherwise.
bool assign_to_job(KernelContext &context, uint64_t job, const std::shared_ptr<class ProcessObject> &process, uint32_t &error);

}

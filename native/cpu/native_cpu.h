#pragma once

#include "pe/loaded_image.h"
#include "pe/module_set.h"

#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include <string>
#include <sys/user.h>
#include <utility>

namespace raven {

enum class NativeStop { returned, syscall, fault, timeout, api, exception, exited };

// x86 runs 32-bit guest code in host compatibility mode; every guest address stays below 4 GiB.
enum class NativeMode { x64, x86 };

struct NativeResult {
	NativeStop stop;
	uint64_t value;
	uint64_t instruction;
	int signal;
	uint64_t fault_address = 0;
	int signal_code = 0;
	uint32_t exception_flags = 0;
	std::vector<uint64_t> exception_information{};
};

struct NativeContext {
	user_regs_struct registers;
	std::vector<uint8_t> xstate;
};

// Everything that distinguishes one guest thread from another while the process is stopped between API calls.
struct NativeThreadState {
	NativeContext context;
	std::vector<NativeContext> callbacks;
	std::vector<uint32_t> callback_cleanups;
	bool active_call = false, awaiting_api = false, awaiting_syscall = false, debug_print_fault = false;
	uint32_t pending_cleanup = 0;
	uint64_t stack_top = 0;
};

// Images must outlive this stopped/resumable x86-64 Linux process.
class NativeProcess {
public:
	NativeProcess(std::span<LoadedImage *const> images, const std::string &bootstrap,
		std::chrono::milliseconds setup_timeout, NativeMode mode = NativeMode::x64);
	~NativeProcess();
	NativeProcess(const NativeProcess &) = delete;
	NativeProcess &operator=(const NativeProcess &) = delete;
	NativeResult call(uint64_t address, std::span<const uint64_t> arguments, std::chrono::milliseconds timeout);
	NativeResult callback(uint64_t address, std::span<const uint64_t> arguments, std::chrono::milliseconds timeout);
	NativeResult resume(std::chrono::milliseconds timeout);
	NativeContext context() const;
	void set_context(const NativeContext &context);
	std::vector<uint8_t> read_memory(uint64_t address, size_t size) const;
	void write_memory(uint64_t address, std::span<const uint8_t> bytes);
	void validate_write_memory(uint64_t address,size_t size) const;
	// Host primitives; Windows reservation/commit and PAGE_* semantics belong above this boundary.
	uint64_t map_memory(size_t size, int protection, uint64_t address = 0);
	void protect_memory(uint64_t address, size_t size, int protection);
	// The same for pages of a mapped program image, which the program may protect although it did not allocate them.
	void protect_image(uint64_t address, size_t size, int protection);
	void unmap_memory(uint64_t address);
	// Maps a host-owned memfd into the guest at a fresh address; release it with unmap_memory.
	uint64_t map_shared(int descriptor, size_t size);
	bool memory_available(uint64_t address, size_t size) const;
	void discard_memory(uint64_t address, size_t size);
	// Dynamic image mappings share LoadedImage storage; the loader owns initialization and lifetime.
	void map_image(LoadedImage &image);
	void unmap_image(uint64_t address);
	std::pair<uint64_t, uint64_t> stack_bounds() const;
	bool active() const;
	void abandon_call();
	// callee_cleanup is the stdcall argument byte count an x86 API pops on return; x64 ignores it.
	void add_api_trap(uint64_t address, uint32_t callee_cleanup = 0);
	NativeMode mode() const;
	// x86 only: FS addresses the 4 KiB TEB at base through a host LDT descriptor.
	void set_teb(uint64_t base);
	void enter_nt_service(uint64_t instruction, uint32_t number);
	void complete_debug_print(uint64_t instruction);
	// Address the guest returns to when a host-initiated call finishes.
	uint64_t return_gate() const;
	size_t callback_depth() const;
	// Diagnostics: RAX after an API result was delivered, without fetching the extended state.
	uint64_t result_register() const;
	// Diagnostics: a hardware write watchpoint (eight bytes) that reports as a fault with si_code TRAP_HWBKPT; address zero clears it.
	void watch_write(uint64_t address);
	// Diagnostics: single-step the next count instructions of the guest, reporting each instruction pointer to the sink.
	void trace_instructions(size_t count, std::function<void(uint64_t)> sink);
	// Guest threads share one traced process: the scheduler saves the running thread and loads the next between API calls.
	NativeThreadState save_thread() const;
	void load_thread(const NativeThreadState &thread);
	// A thread that has not started: no active call, its own stack ceiling and TEB (x64 GS base).
	NativeThreadState new_thread(uint64_t stack_top, uint64_t teb);
	// A fault stop becomes an API-style stop, so host code may run guest callbacks and redirect execution.
	void enter_fault_dispatch();
	// Continues the guest at a new context, dropping callbacks nested above depth (exception unwinding abandons them).
	void redirect(const NativeContext &context, size_t depth);
	std::vector<uint64_t> api_arguments(size_t count) const;
	// Replaces one stdcall argument word of the pending x86 API call, so an adapter can forward the call to another handler.
	void set_api_argument(size_t index, uint32_t value);
	// Runs a handler written for x64 argument conventions on behalf of a 32-bit call: api_arguments and api_float_arguments answer from the
	// given words, and return_api keeps its value for end_translated_call instead of resuming the guest.
	// Lets a guest that runs for `slice` without stopping be interrupted so that `yield` can give the processor to another thread; `wanted` says
	// whether there is another thread to give it to.
	void set_time_slicing(std::chrono::milliseconds slice, std::function<bool()> wanted, std::function<void()> yield);
	void begin_translated_call(std::vector<uint64_t> words, std::array<uint64_t, 4> floats);
	uint64_t end_translated_call();
	// Low 64 bits of XMM0 to XMM3, where an x64 caller passes the first four floating-point arguments.
	std::array<uint64_t, 4> api_float_arguments() const;
	void return_api(uint64_t value);

private:
	void protect_range(uint64_t address, size_t size, int protection, bool image);
	struct State;
	std::unique_ptr<State> state;
	void install_segment(uint32_t entry, uint64_t base);
	uint64_t memory_syscall(uint64_t number, uint64_t a1, uint64_t a2, uint64_t a3 = 0,
		uint64_t a4 = 0, uint64_t a5 = 0);
	NativeResult begin_call(uint64_t address, std::span<const uint64_t> arguments,
		uint64_t stack_ceiling, std::chrono::milliseconds timeout);
	NativeResult begin_x86_call(uint64_t address, std::span<const uint64_t> arguments,
		uint64_t stack_ceiling, std::chrono::milliseconds timeout);
};

// Runs one import-free PE64 entry. This is not Windows process initialization.
NativeResult run_native_entry(const PEImage &image, LoadedImage &loaded,
	const std::string &bootstrap, std::chrono::milliseconds timeout);

// Binds and maps supplied modules; DLLs with startup code still require loader initialization.
NativeResult run_native_modules(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout);

}

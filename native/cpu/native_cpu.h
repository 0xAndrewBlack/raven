#pragma once

#include "pe/loaded_image.h"
#include "pe/module_set.h"

#include <chrono>
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
	void unmap_memory(uint64_t address);
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
	std::vector<uint64_t> api_arguments(size_t count) const;
	void return_api(uint64_t value);

private:
	struct State;
	std::unique_ptr<State> state;
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

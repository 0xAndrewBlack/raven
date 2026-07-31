#pragma once

#include "cpu/native_cpu.h"
#include "pe/module_set.h"

#include <optional>
#include <vector>

namespace raven {

// x64 CONTEXT (1232 bytes) as raw guest bytes, with the register slots the unwinder touches.
namespace x64_context {
inline constexpr size_t size = 1232, flags = 0x30, mxcsr = 0x34, eflags = 0x44, general = 0x78, rsp = 0x98, rip = 0xf8, float_area = 0x100;
inline constexpr uint32_t full_flags = 0x10000f;
}

using ContextBytes = std::vector<uint8_t>;
uint64_t context_register(const ContextBytes &context, size_t number);
void set_context_register(ContextBytes &context, size_t number, uint64_t value);
uint64_t context_rip(const ContextBytes &context);
uint64_t context_rsp(const ContextBytes &context);
void set_context_rip(ContextBytes &context, uint64_t value);
void set_context_rsp(ContextBytes &context, uint64_t value);
ContextBytes context_from_process(const NativeContext &native);
// Writes the registers a CONTEXT describes into a native context, keeping its other state.
void apply_context(NativeContext &native, const ContextBytes &context);

struct FunctionEntry {
	uint64_t address = 0;
	uint32_t begin = 0, end = 0, unwind = 0;
	uint64_t image_base = 0;
	const PEModule *module = nullptr;
};

// Table-based x64 stack unwinding over the loaded modules' exception directories.
class NativeUnwinder {
public:
	NativeUnwinder(NativeProcess &process, const ModuleSet &modules) : process(process), modules(modules) {}
	std::optional<FunctionEntry> lookup(uint64_t pc) const;
	const PEModule *module_at(uint64_t address) const;
	struct Result {
		uint64_t handler = 0, handler_data = 0, establisher = 0;
	};
	// Moves the context from the callee's frame to its caller's; handler_type is UNW_FLAG_EHANDLER (1) or UNW_FLAG_UHANDLER (2).
	Result unwind(uint32_t handler_type, uint64_t pc, const FunctionEntry &function, ContextBytes &context) const;
	// A function without unwind data is a leaf: its caller's return address is on top of the stack.
	void unwind_leaf(ContextBytes &context) const;

private:
	NativeProcess &process;
	const ModuleSet &modules;
	bool epilogue(uint64_t pc, ContextBytes &context) const;
};

}

#include "kernel_context.h"
#include "exceptions.h"
#include "unwind.h"

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

namespace raven {

namespace {

constexpr size_t record_size = 152;
constexpr uint32_t flag_noncontinuable = 1, flag_unwinding = 2, flag_exit_unwind = 4, flag_target_unwind = 0x20, flag_nested = 0x10;
constexpr uint32_t status_unwind = 0xc0000027U, status_noncontinuable = 0xc0000025U, status_invalid_disposition = 0xc0000026U;
// DISPATCHER_CONTEXT is 80 bytes; the fields below are its byte offsets.
constexpr size_t dispatcher_size = 80;

uint32_t le32(const std::vector<uint8_t> &bytes, size_t at)
{
	uint32_t value;
	std::memcpy(&value, bytes.data() + at, 4);
	return value;
}

void put32(std::vector<uint8_t> &bytes, size_t at, uint32_t value)
{
	std::memcpy(bytes.data() + at, &value, 4);
}

void put64(std::vector<uint8_t> &bytes, size_t at, uint64_t value)
{
	std::memcpy(bytes.data() + at, &value, 8);
}

// Bump allocation of guest scratch memory for records and contexts; released when the outermost dispatch ends.
class Scratch {
public:
	explicit Scratch(KernelContext &context) : context(context) {}
	uint64_t take(size_t size)
	{
		if (!base) {
			const auto range = context.memory.allocate(0, capacity, 0x3000, 4);
			if (range.status)
				throw std::runtime_error("native exception dispatch cannot reserve guest memory");
			base = range.address;
		}
		top = (top + 15) & ~size_t(15);
		if (top + size > capacity)
			throw std::runtime_error("native exception dispatch exhausted its guest memory");
		const uint64_t address = base + top;
		top += size;
		return address;
	}
	size_t mark() const { return top; }
	void release(size_t to) { top = to; }

private:
	KernelContext &context;
	uint64_t base = 0;
	size_t top = 0;
	static constexpr size_t capacity = 1 << 20;
};

}

class Exceptions {
public:
	Exceptions(KernelContext &context, NativeUnwinder &unwinder) : context(context), unwinder(unwinder), scratch(context) {}

	bool trace = std::getenv("RAVEN_TRACE_SEH") != nullptr;

	// Walks the stack from the raising frame; true when a handler resumed execution through `resume`.
	bool dispatch(std::vector<uint8_t> record, ContextBytes origin, ContextBytes &resume)
	{
		const size_t mark = scratch.mark();
		const uint64_t guest_record = scratch.take(record_size);
		const uint64_t dispatcher = scratch.take(dispatcher_size);
		const uint64_t frame_context = scratch.take(x64_context::size);
		context.process.write_memory(guest_record, record);
		active.push_back({origin, context.process.callback_depth()});
		if (trace)
			std::fprintf(stderr, "seh dispatch begin: code=%x active=%zu depth=%zu\n", le32(record, 0), active.size(), context.process.callback_depth());
		bool handled = false;
		ContextBytes current = origin;
		for (int frames = 0; frames < 1024; ++frames) {
			const uint64_t pc = context_rip(current);
			if (!pc)
				break;
			const auto function = unwinder.lookup(pc);
			if (!function) {
				// The host callback boundary ends the search: no frames of the guest's caller are on this stack.
				if (pc == context.process.return_gate() || !readable(pc))
					break;
				unwinder.unwind_leaf(current);
				continue;
			}
			ContextBytes next = current;
			const auto result = unwinder.unwind(1, pc, *function, next);
			if (trace)
				std::fprintf(stderr, "seh frame: pc=%llx function=%x..%x unwind=%x handler=%llx\n", (unsigned long long)pc, function->begin, function->end,
					function->unwind, (unsigned long long)result.handler);
			if (result.handler) {
				std::vector<uint8_t> frame = current;
				context.process.write_memory(frame_context, frame);
				std::vector<uint8_t> descriptor(dispatcher_size);
				put64(descriptor, 0, pc);
				put64(descriptor, 8, function->image_base);
				put64(descriptor, 0x10, function->address);
				put64(descriptor, 0x18, result.establisher);
				put64(descriptor, 0x20, 0);
				put64(descriptor, 0x28, frame_context);
				put64(descriptor, 0x30, result.handler);
				put64(descriptor, 0x38, result.handler_data);
				put64(descriptor, 0x40, 0);
				context.process.write_memory(dispatcher, descriptor);
				if (trace)
					std::fprintf(stderr, "seh: pc=%llx handler=%llx frame=%llx\n", (unsigned long long)pc, (unsigned long long)result.handler, (unsigned long long)result.establisher);
				const uint64_t arguments[] = {guest_record, result.establisher, frame_context, dispatcher};
				const auto outcome = context.call(result.handler, arguments);
				if (outcome.stop != NativeStop::returned)
					throw outcome;
				const uint32_t disposition = uint32_t(outcome.value);
				if (disposition == 0) {
					if (le32(record, 4) & flag_noncontinuable)
						throw std::runtime_error("native exception handler continued a noncontinuable exception");
					resume = context.process.read_memory(frame_context, x64_context::size);
					handled = true;
					break;
				}
				if (disposition != 1 && disposition != 2)
					throw std::runtime_error("native exception handler returned an invalid disposition");
			}
			current = next;
		}
		if (trace)
			std::fprintf(stderr, "seh dispatch end: handled=%d active=%zu\n", handled, active.size());
		active.pop_back();
		scratch.release(mark);
		return handled;
	}

	// Handles one exception end to end; either redirects the guest (throwing ExecutionRedirected) or ends the process.
	[[noreturn]] void raise(std::vector<uint8_t> record, ContextBytes origin, const std::function<NativeResult()> &unhandled)
	{
		ContextBytes resume;
		const size_t depth = context.process.callback_depth();
		if (dispatch(record, origin, resume))
			redirect_to(resume, depth);
		if (context.unhandled_filter) {
			const size_t mark = scratch.mark();
			const uint64_t guest_record = scratch.take(record_size), guest_context = scratch.take(x64_context::size), pointers = scratch.take(16);
			context.process.write_memory(guest_record, record);
			context.process.write_memory(guest_context, origin);
			std::vector<uint8_t> block(16);
			put64(block, 0, guest_record);
			put64(block, 8, guest_context);
			context.process.write_memory(pointers, block);
			const uint64_t arguments[] = {pointers};
			const auto outcome = context.call(context.unhandled_filter, arguments);
			if (outcome.stop != NativeStop::returned)
				throw outcome;
			if (int32_t(outcome.value) == -1) {
				resume = context.process.read_memory(guest_context, x64_context::size);
				scratch.release(mark);
				redirect_to(resume, depth);
			}
			scratch.release(mark);
		}
		const uint32_t code = le32(record, 0);
		std::fprintf(stderr, "raven: unhandled exception %08x at %llx\n", code, (unsigned long long)context_rip(origin));
		throw unhandled();
	}

	// Execution resumes at the callback nesting where the exception was raised; handler calls above it are abandoned.
	[[noreturn]] void redirect_to(const ContextBytes &target, size_t depth)
	{
		auto native = context.process.context();
		apply_context(native, target);
		context.process.redirect(native, depth);
		active.clear();
		scratch.release(0);
		throw ExecutionRedirected{depth};
	}

	// The caller's context at a trapped API call: the return address on top of the stack is the next instruction.
	ContextBytes caller_context()
	{
		auto native = context.process.context();
		auto bytes = context_from_process(native);
		const uint64_t rsp = context_rsp(bytes);
		const auto top = context.process.read_memory(rsp, 8);
		uint64_t rip;
		std::memcpy(&rip, top.data(), 8);
		set_context_rip(bytes, rip);
		set_context_rsp(bytes, rsp + 8);
		return bytes;
	}

	std::vector<uint8_t> new_record(uint32_t code, uint32_t flags, uint64_t address, std::span<const uint64_t> parameters)
	{
		std::vector<uint8_t> record(record_size);
		put32(record, 0, code);
		put32(record, 4, flags);
		put64(record, 0x10, address);
		put32(record, 0x18, uint32_t(parameters.size()));
		for (size_t index = 0; index < parameters.size(); ++index)
			put64(record, 0x20 + index * 8, parameters[index]);
		return record;
	}

	// Second pass: runs termination handlers frame by frame up to the target, then resumes there.
	[[noreturn]] void unwind(uint64_t target_frame, uint64_t target_ip, std::vector<uint8_t> record, uint64_t return_value)
	{
		put32(record, 4, le32(record, 4) | flag_unwinding | (target_frame ? 0 : flag_exit_unwind));
		// The outermost dispatch being unwound marks where the callback nesting returns to.
		const size_t depth = active.empty() ? context.process.callback_depth() : active.front().depth;
		const size_t mark = scratch.mark();
		const uint64_t guest_record = scratch.take(record_size);
		const uint64_t dispatcher = scratch.take(dispatcher_size);
		const uint64_t frame_context = scratch.take(x64_context::size);
		ContextBytes current = caller_context();
		bool reached = false;
		for (int frames = 0; frames < 1024 && !reached; ++frames) {
			const uint64_t pc = context_rip(current);
			if (pc == context.process.return_gate() && !active.empty()) {
				// The host callback boundary stands in for the dispatcher's own frames: continue from where the exception was raised.
				current = active.back().origin;
				active.pop_back();
				continue;
			}
			if (!pc)
				break;
			const auto function = unwinder.lookup(pc);
			if (!function) {
				unwinder.unwind_leaf(current);
				continue;
			}
			ContextBytes next = current;
			const auto result = unwinder.unwind(2, pc, *function, next);
			const bool at_target = target_frame && result.establisher == target_frame;
			if (target_frame && result.establisher > target_frame && !at_target) {
				std::fprintf(stderr, "raven: unwind passed its target frame\n");
				context.process.abandon_call();
				throw ProcessExit{status_invalid_disposition, pc};
			}
			if (result.handler) {
				put32(record, 4, (le32(record, 4) & ~flag_target_unwind) | (at_target ? flag_target_unwind : 0));
				context.process.write_memory(guest_record, record);
				context.process.write_memory(frame_context, current);
				std::vector<uint8_t> descriptor(dispatcher_size);
				put64(descriptor, 0, pc);
				put64(descriptor, 8, function->image_base);
				put64(descriptor, 0x10, function->address);
				put64(descriptor, 0x18, result.establisher);
				put64(descriptor, 0x20, target_ip);
				put64(descriptor, 0x28, frame_context);
				put64(descriptor, 0x30, result.handler);
				put64(descriptor, 0x38, result.handler_data);
				context.process.write_memory(dispatcher, descriptor);
				if (trace)
					std::fprintf(stderr, "seh unwind: pc=%llx handler=%llx frame=%llx%s\n", (unsigned long long)pc, (unsigned long long)result.handler,
						(unsigned long long)result.establisher, at_target ? " target" : "");
				const uint64_t arguments[] = {guest_record, result.establisher, frame_context, dispatcher};
				const auto outcome = context.call(result.handler, arguments);
				if (outcome.stop != NativeStop::returned)
					throw outcome;
				// Handlers may adjust the frame's context (nested C++ cleanup does); take it back.
				if (uint32_t(outcome.value) == 3)
					current = context.process.read_memory(frame_context, x64_context::size);
			}
			if (at_target) {
				reached = true;
				break;
			}
			current = next;
		}
		scratch.release(mark);
		if (!reached && target_frame) {
			std::fprintf(stderr, "raven: unwind never reached its target frame\n");
			context.process.abandon_call();
			throw ProcessExit{status_invalid_disposition, context_rip(current)};
		}
		if (target_ip)
			set_context_rip(current, target_ip);
		set_context_register(current, 0, return_value);
		redirect_to(current, depth);
	}

	struct Active {
		ContextBytes origin;
		size_t depth;
	};
	std::vector<Active> active;

private:
	KernelContext &context;
	NativeUnwinder &unwinder;
	Scratch scratch;
	bool readable(uint64_t address) const
	{
		try {
			context.process.read_memory(address, 1);
			return true;
		} catch (const std::runtime_error &) {
			return false;
		}
	}
};

void register_exception_api(ApiRegistry &registry, KernelContext &context, NativeUnwinder &unwinder)
{
	auto exceptions = std::make_shared<Exceptions>(context, unwinder);
	context.raise_fault = [exceptions, &context](const NativeResult &fault) {
		auto native = context.process.context();
		auto origin = context_from_process(native);
		const uint64_t rip = context_rip(origin);
		const auto code = context.process.read_memory(rip, 2);
		if (fault.signal == SIGSEGV && code[0] == 0xcd && code[1] == 0x29) {
			std::fprintf(stderr, "raven: fast fail %llu\n", (unsigned long long)context_register(origin, 1));
			context.process.abandon_call();
			throw ProcessExit{0xc0000409U, rip};
		}
		uint32_t status = 0xc0000005U;
		std::vector<uint64_t> parameters;
		switch (fault.signal) {
		case SIGSEGV: parameters = {0, fault.fault_address}; break;
		case SIGBUS: status = 0xc0000006U; parameters = {0, fault.fault_address, 0xc0000006U}; break;
		case SIGFPE:
			status = fault.signal_code == FPE_INTDIV ? 0xc0000094U : fault.signal_code == FPE_INTOVF ? 0xc0000095U :
				fault.signal_code == FPE_FLTDIV ? 0xc000008eU : fault.signal_code == FPE_FLTOVF ? 0xc0000091U : 0xc000008fU;
			break;
		case SIGILL: status = 0xc000001dU; break;
		case SIGTRAP: status = 0x80000003U; break;
		default: break;
		}
		context.process.enter_fault_dispatch();
		auto record = exceptions->new_record(status, 0, rip, parameters);
		exceptions->raise(std::move(record), std::move(origin), [fault] { return fault; });
	};
	registry.add("RtlCaptureContext", 1, [exceptions, &context](ApiCall &call) {
		call.write(call[0], exceptions->caller_context());
	});
	registry.add("RtlLookupFunctionEntry", 3, [&unwinder](ApiCall &call) {
		const auto function = unwinder.lookup(call[0]);
		if (call[1]) call.store<uint64_t>(call[1], function ? function->image_base : 0);
		call.ret(function ? function->address : 0);
	});
	registry.add("RtlPcToFileHeader", 2, [&unwinder](ApiCall &call) {
		const auto *module = unwinder.module_at(call[0]);
		const uint64_t base = module ? module->loaded.base() : 0;
		if (call[1]) call.store<uint64_t>(call[1], base);
		call.ret(base);
	});
	registry.add("RtlVirtualUnwind", 8, [&unwinder](ApiCall &call) {
		const auto entry = call.read(call[3], 12);
		FunctionEntry function;
		function.address = call[3];
		std::memcpy(&function.begin, entry.data(), 4);
		std::memcpy(&function.end, entry.data() + 4, 4);
		std::memcpy(&function.unwind, entry.data() + 8, 4);
		function.image_base = call[1];
		function.module = unwinder.module_at(call[1]);
		if (!function.module) {
			call.fail(87);
			return;
		}
		auto bytes = call.read(call[4], x64_context::size);
		const auto result = unwinder.unwind(call.u32(0), call[2], function, bytes);
		call.write(call[4], bytes);
		if (call[5]) call.store<uint64_t>(call[5], result.handler_data);
		if (call[6]) call.store<uint64_t>(call[6], result.establisher);
		call.ret(result.handler);
	});
	registry.add("RaiseException", 4, [exceptions, &context](ApiCall &call) {
		const uint32_t count = std::min<uint32_t>(call.u32(2), 15);
		std::vector<uint64_t> parameters(count);
		for (uint32_t index = 0; call[3] && index < count; ++index)
			parameters[index] = call.load<uint64_t>(call[3] + index * 8ULL);
		auto origin = exceptions->caller_context();
		auto record = exceptions->new_record(call.u32(0), call.u32(1) & flag_noncontinuable, context_rip(origin), parameters);
		exceptions->raise(std::move(record), std::move(origin), [&context] { return native_raise_exception(context.process); });
	});
	registry.add("RtlRaiseException", 1, [exceptions, &context](ApiCall &call) {
		auto origin = exceptions->caller_context();
		auto record = call.read(call[0], record_size);
		put64(record, 0x10, context_rip(origin));
		exceptions->raise(std::move(record), std::move(origin), [&context] { return native_raise_rtl_exception(context.process, false); });
	});
	registry.add("RtlUnwindEx", 6, [exceptions](ApiCall &call) {
		std::vector<uint8_t> record;
		if (call[2])
			record = call.read(call[2], record_size);
		else
			record = exceptions->new_record(status_unwind, 0, 0, {});
		exceptions->unwind(call[0], call[1], std::move(record), call[3]);
	});
	registry.add("RtlUnwind", 4, [exceptions](ApiCall &call) {
		std::vector<uint8_t> record;
		if (call[2])
			record = call.read(call[2], record_size);
		else
			record = exceptions->new_record(status_unwind, 0, 0, {});
		exceptions->unwind(call[0], call[1], std::move(record), call[3]);
	});
	const auto restore = [exceptions, &context](ApiCall &call) {
		exceptions->redirect_to(call.read(call[0], x64_context::size), context.process.callback_depth());
	};
	registry.add("RtlRestoreContext", 2, restore);
	registry.add("NtContinue", 2, restore);
	registry.add("UnhandledExceptionFilter", 1, [](ApiCall &call) { call.ret(0); });
	registry.add("RtlAddFunctionTable", 3, [](ApiCall &call) { call.ret(1); });
	registry.add("RtlDeleteFunctionTable", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("RtlInstallFunctionTableCallback", 6, [](ApiCall &call) { call.ret(1); });
	(void)status_noncontinuable;
	(void)flag_nested;
}

}

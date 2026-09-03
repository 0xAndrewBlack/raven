#include "child_process.h"
#include "kernel_context.h"
#include "text.h"

#include <algorithm>
#include <chrono>
#include <map>

namespace raven {

namespace {

constexpr uint64_t current_thread_pseudo = UINT64_MAX - 1;
constexpr uint32_t wait_timeout = 0x102, wait_failed = UINT32_MAX, wait_io_completion = 0xc0, wait_abandoned = 0x80;

class MutexObject : public KernelObject {
public:
	int signaled(uint32_t thread) const override { return owner == 0 || owner == thread; }
	void consume(uint32_t thread) override
	{
		owner = thread;
		++recursion;
	}
	uint32_t owner = 0;
	int recursion = 0;
};

class SemaphoreObject : public KernelObject {
public:
	int signaled(uint32_t) const override { return count > 0; }
	void consume(uint32_t) override { --count; }
	int64_t count = 0, maximum = 0;
};

class WorkObject : public KernelObject {
public:
	uint64_t callback = 0, parameter = 0;
	std::vector<std::shared_ptr<GuestThread>> running;
};

}

void register_thread_api(ApiRegistry &registry, KernelContext &context)
{
	auto &threads = context.threads;
	auto &objects = context.objects;
	// Thread handles are per object; one thread object per guest thread keeps handle identity stable.
	auto handle_of = std::make_shared<std::map<uint32_t, std::shared_ptr<ThreadObject>>>();
	const auto thread_from = [&threads, &objects](uint64_t handle) -> std::shared_ptr<GuestThread> {
		if (handle == current_thread_pseudo)
			return threads.find(threads.current_id());
		const auto object = objects.object_as<ThreadObject>(handle);
		return object ? object->thread : nullptr;
	};

	const auto run_apcs = [&context, &threads]() {
		auto &me = threads.current();
		bool ran = false;
		while (!me.apcs.empty()) {
			const auto apc = me.apcs.front();
			me.apcs.pop_front();
			const uint64_t arguments[] = {apc.parameter};
			const auto result = context.call(apc.routine, arguments);
			if (result.stop != NativeStop::returned)
				throw result;
			ran = true;
		}
		return ran;
	};
	// Waits for any or all of the handles; returns the Windows wait code.
	const auto wait = [&objects, &threads, run_apcs](ApiCall &call, const std::vector<uint64_t> &handles, bool all, uint32_t milliseconds, bool alertable) -> uint32_t {
		const uint32_t id = threads.current_id();
		if (handles.empty() || handles.size() > 64) {
			call.set_last_error(87);
			return wait_failed;
		}
		std::vector<uint64_t> resolved = handles;
		for (auto &handle : resolved)
			if (handle == current_thread_pseudo) {
				call.set_last_error(6);
				return wait_failed;
			}
		const auto states = [&]() {
			std::vector<int> result;
			for (const auto handle : resolved)
				result.push_back(objects.signaled(handle, id));
			return result;
		};
		std::optional<std::chrono::steady_clock::time_point> wake;
		if (milliseconds != UINT32_MAX)
			wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
		for (;;) {
			const auto current = states();
			for (const auto state : current)
				if (state < 0) {
					call.set_last_error(6);
					return wait_failed;
				}
			if (all) {
				if (std::all_of(current.begin(), current.end(), [](int state) { return state == 1; })) {
					for (const auto handle : resolved)
						objects.consume(handle, id);
					return 0;
				}
			} else {
				for (size_t index = 0; index < current.size(); ++index)
					if (current[index] == 1) {
						objects.consume(resolved[index], id);
						return uint32_t(index);
					}
			}
			if (alertable && !threads.current().apcs.empty() && run_apcs())
				return wait_io_completion;
			if (milliseconds == 0 || (wake && std::chrono::steady_clock::now() >= *wake))
				return wait_timeout;
			threads.block([&] {
				const auto now = states();
				if (alertable && !threads.current().apcs.empty())
					return true;
				return all ? std::all_of(now.begin(), now.end(), [](int state) { return state == 1; }) :
					std::any_of(now.begin(), now.end(), [](int state) { return state == 1; });
			}, wake);
		}
	};
	registry.add("WaitForSingleObject", 2, [wait](ApiCall &call) { call.ret(wait(call, {call[0]}, false, call.u32(1), false)); });
	registry.add("WaitForSingleObjectEx", 3, [wait](ApiCall &call) { call.ret(wait(call, {call[0]}, false, call.u32(1), call.u32(2))); });
	const auto multiple = [wait](ApiCall &call, bool alertable) {
		const uint32_t count = call.u32(0);
		if (count > 64 || !call[1]) {
			call.fail(87, wait_failed);
			return;
		}
		std::vector<uint64_t> handles(count);
		for (uint32_t index = 0; index < count; ++index)
			handles[index] = call.load<uint64_t>(call[1] + index * 8ULL);
		call.ret(wait(call, handles, call.u32(2), call.u32(3), alertable));
	};
	registry.add("WaitForMultipleObjects", 4, [multiple](ApiCall &call) { multiple(call, false); });
	registry.add("WaitForMultipleObjectsEx", 5, [multiple](ApiCall &call) { multiple(call, call.u32(4)); });
	// Waits for handles or for window input: the wait code one past the last handle reports a message.
	const auto message_wait = [&context, &objects, &threads](ApiCall &call, uint32_t count, uint64_t array, bool all, uint32_t milliseconds) {
		if (count > 63) {
			call.fail(87, wait_failed);
			return;
		}
		std::vector<uint64_t> handles(count);
		for (uint32_t index = 0; index < count; ++index)
			handles[index] = call.load<uint64_t>(array + index * 8ULL);
		const uint32_t id = threads.current_id();
		std::optional<std::chrono::steady_clock::time_point> wake;
		if (milliseconds != UINT32_MAX)
			wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
		const auto ready = [&]() -> std::optional<uint32_t> {
			if (context.message_ready && context.message_ready())
				return count;
			std::vector<int> states;
			for (const auto handle : handles)
				states.push_back(objects.signaled(handle, id));
			if (all && count && std::all_of(states.begin(), states.end(), [](int s) { return s == 1; })) {
				for (const auto handle : handles)
					objects.consume(handle, id);
				return 0;
			}
			if (!all)
				for (size_t index = 0; index < states.size(); ++index)
					if (states[index] == 1) {
						objects.consume(handles[index], id);
						return uint32_t(index);
					}
			return std::nullopt;
		};
		for (;;) {
			if (const auto code = ready()) {
				call.ret(*code);
				return;
			}
			if (milliseconds == 0 || (wake && std::chrono::steady_clock::now() >= *wake)) {
				call.ret(wait_timeout);
				return;
			}
			threads.block([&] {
				if (context.message_ready && context.message_ready())
					return true;
				for (const auto handle : handles)
					if (objects.signaled(handle, id) == 1)
						return true;
				return false;
			}, wake);
		}
	};
	registry.add("MsgWaitForMultipleObjects", 5, [message_wait](ApiCall &call) { message_wait(call, call.u32(0), call[1], call.u32(2), call.u32(3)); });
	registry.add("MsgWaitForMultipleObjectsEx", 5, [message_wait](ApiCall &call) { message_wait(call, call.u32(0), call[1], call.u32(4) & 1, call.u32(2)); });
	registry.add("SignalObjectAndWait", 4, [wait, &objects](ApiCall &call) {
		if (objects.signaled(call[0], 0) == -2) {
			call.fail(6, wait_failed);
			return;
		}
		call.ret(wait(call, {call[1]}, false, call.u32(2), call.u32(3)));
	});
	registry.add("Sleep", 1, [&threads](ApiCall &call) {
		const uint32_t milliseconds = call.u32(0);
		if (!milliseconds) {
			threads.yield();
			return;
		}
		std::optional<std::chrono::steady_clock::time_point> wake;
		if (milliseconds != UINT32_MAX)
			wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
		threads.block([] { return false; }, wake);
	});
	registry.add("SleepEx", 2, [&threads, run_apcs](ApiCall &call) {
		const uint32_t milliseconds = call.u32(0);
		const bool alertable = call.u32(1);
		if (alertable && run_apcs()) {
			call.ret(wait_io_completion);
			return;
		}
		if (!milliseconds) {
			threads.yield();
			return;
		}
		std::optional<std::chrono::steady_clock::time_point> wake;
		if (milliseconds != UINT32_MAX)
			wake = std::chrono::steady_clock::now() + std::chrono::milliseconds(milliseconds);
		threads.block([&threads, alertable] { return alertable && !threads.current().apcs.empty(); }, wake);
		if (alertable && run_apcs())
			call.ret(wait_io_completion);
	});
	registry.add("SwitchToThread", 0, [&threads](ApiCall &call) { call.ret(threads.yield()); });

	registry.add("CreateThread", 6, [&, handle_of](ApiCall &call) {
		const uint32_t flags = call.u32(4);
		if (flags & ~(0x4U | 0x10000U)) {
			call.fail(87);
			return;
		}
		std::shared_ptr<GuestThread> thread;
		try {
			thread = threads.create(call[2], call[3], call[1] ? call[1] : 1024 * 1024, flags & 4);
		} catch (const std::runtime_error &) {
			call.fail(8);
			return;
		}
		auto object = std::make_shared<ThreadObject>(thread);
		const auto made = objects.add_object(object);
		if (made.status) {
			threads.terminate(thread, 0);
			call.fail(8);
			return;
		}
		(*handle_of)[thread->id] = object;
		if (call[5]) call.store<uint32_t>(call[5], thread->id);
		call.ret(made.value);
	});
	registry.add("ExitThread", 1, [&threads](ApiCall &call) { threads.exit_current(call.u32(0)); });
	registry.add("FreeLibraryAndExitThread", 2, [&threads](ApiCall &call) { threads.exit_current(call.u32(1)); });
	registry.add("GetExitCodeThread", 2, [thread_from](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		if (!thread) {
			call.fail(6);
			return;
		}
		call.store<uint32_t>(call[1], thread->state == GuestThread::State::done ? thread->exit_code : 259);
		call.ret(1);
	});
	registry.add("TerminateThread", 2, [thread_from, &threads](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		if (!thread) {
			call.fail(6);
			return;
		}
		threads.terminate(thread, call.u32(1));
		call.ret(1);
	});
	registry.add("SuspendThread", 1, [thread_from](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		if (!thread) {
			call.fail(6, UINT32_MAX);
			return;
		}
		call.ret(uint32_t(thread->suspend_count++));
	});
	registry.add("ResumeThread", 1, [thread_from, &objects](ApiCall &call) {
		// The main thread of a child that was started suspended runs when this opens its gate.
		if (const auto child = objects.object_as<ChildThreadObject>(call[0])) {
			call.ret(child->resume());
			return;
		}
		const auto thread = thread_from(call[0]);
		if (!thread) {
			call.fail(6, UINT32_MAX);
			return;
		}
		const auto previous = thread->suspend_count;
		if (thread->suspend_count > 0)
			--thread->suspend_count;
		call.ret(uint32_t(previous));
	});
	// The registers of a thread as a CONTEXT (x64): the control and integer groups, from where the thread stopped.
	registry.add("GetThreadContext", 2, [thread_from, &threads](ApiCall &call) {
		if (call.pointer_width() == 4 || !call[1]) {
			call.fail(call[1] ? 50 : 87);
			return;
		}
		const auto thread = thread_from(call[0]);
		if (!thread) {
			call.fail(6);
			return;
		}
		const auto &registers = thread->id == threads.current_id() ? call.process.context().registers : thread->snapshot.context.registers;
		const uint32_t flags = call.load<uint32_t>(call[1] + 0x30);
		const auto put = [&](size_t at, uint64_t value) { call.store<uint64_t>(call[1] + at, value); };
		if (flags & 0x1) {
			call.store<uint16_t>(call[1] + 0x38, uint16_t(registers.cs));
			call.store<uint16_t>(call[1] + 0x42, uint16_t(registers.ss));
			call.store<uint32_t>(call[1] + 0x44, uint32_t(registers.eflags));
			put(0x98, registers.rsp);
			put(0xa0, registers.rbp);
			put(0xf8, registers.rip);
		}
		if (flags & 0x2) {
			put(0x78, registers.rax); put(0x80, registers.rcx); put(0x88, registers.rdx); put(0x90, registers.rbx);
			put(0xa8, registers.rsi); put(0xb0, registers.rdi);
			put(0xb8, registers.r8); put(0xc0, registers.r9); put(0xc8, registers.r10); put(0xd0, registers.r11);
			put(0xd8, registers.r12); put(0xe0, registers.r13); put(0xe8, registers.r14); put(0xf0, registers.r15);
		}
		call.ret(1);
	});
	// A thread's description is a name the program gives it; it is kept per thread and handed back in memory the program frees with LocalFree.
	auto descriptions = std::make_shared<std::map<uint32_t, std::u16string>>();
	registry.add("SetThreadDescription", 2, [thread_from, descriptions](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		if (!thread || !call[1]) {
			call.ret(thread ? 0x80070057U : 0x80070006U);
			return;
		}
		(*descriptions)[thread->id] = call.wide(call[1], 4096);
		call.ret(0);
	});
	registry.add("GetThreadDescription", 2, [thread_from, descriptions, &context](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		if (!thread || !call[1]) {
			call.ret(thread ? 0x80070057U : 0x80070006U);
			return;
		}
		const auto found = descriptions->find(thread->id);
		const std::u16string text = found == descriptions->end() ? std::u16string() : found->second;
		const auto memory = context.allocator.allocate((text.size() + 1) * 2, true);
		if (!memory) {
			call.ret(0x8007000eU);
			return;
		}
		call.write(memory, std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(text.data()), text.size() * 2));
		call.store_pointer(call[1], memory);
		call.ret(0);
	});
	registry.add("GetThreadPriorityBoost", 2, [](ApiCall &call) {
		if (call[1])
			call.store<uint32_t>(call[1], 0);
		call.ret(1);
	});
	registry.add("SetThreadPriorityBoost", 2, [](ApiCall &call) { call.ret(1); });
	registry.add("SetThreadInformation", 4, [](ApiCall &call) { call.ret(1); });
	registry.add("GetThreadId", 1, [thread_from](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		call.ret(thread ? thread->id : 0);
		if (!thread) call.set_last_error(6);
	});
	registry.add("GetThreadPriority", 1, [thread_from](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		if (!thread) {
			call.fail(6, 0x7fffffff);
			return;
		}
		call.ret(uint32_t(thread->priority));
	});
	registry.add("SetThreadPriority", 2, [thread_from](ApiCall &call) {
		const auto thread = thread_from(call[0]);
		if (!thread) {
			call.fail(6);
			return;
		}
		thread->priority = call.i32(1);
		call.ret(1);
	});
	registry.add("SetThreadAffinityMask", 2, [](ApiCall &call) { call.ret(1); });
	registry.add("SetThreadStackGuarantee", 1, [](ApiCall &call) { call.ret(1); });
	registry.add("OpenThread", 3, [&threads, &objects, handle_of](ApiCall &call) {
		const auto thread = threads.find(call.u32(2));
		if (!thread) {
			call.fail(87);
			return;
		}
		auto &object = (*handle_of)[thread->id];
		if (!object)
			object = std::make_shared<ThreadObject>(thread);
		const auto made = objects.add_object(object);
		call.ret(made.status ? 0 : made.value);
	});
	registry.add("QueueUserAPC", 3, [thread_from](ApiCall &call) {
		const auto thread = thread_from(call[1]);
		if (!thread) {
			call.fail(6);
			return;
		}
		thread->apcs.push_back({call[0], call[2]});
		call.ret(1);
	});

	// Named events are one object per name inside the process; sharing them with other processes is not done yet.
	registry.add("CreateEventW", 4, [&objects](ApiCall &call) {
		bool existed = false;
		const auto made = call[3] ? objects.create_named_event(call.wide(call[3], 259), 0x1f0003, call.u32(1) ? 0 : 1, call.u32(2) != 0, existed)
			: objects.create_event(0x1f0003, call.u32(1) ? 0 : 1, call.u32(2) != 0);
		if (made.status) {
			call.fail(made.status == 0xc000009aU ? 4 : 87, 0);
			return;
		}
		call.set_last_error(existed ? 183 : 0);
		call.ret(made.value);
	});
	registry.add("OpenEventW", 3, [&objects](ApiCall &call) {
		if (!call[2]) {
			call.fail(87, 0);
			return;
		}
		const auto made = objects.open_named_event(call.wide(call[2], 259), 0x1f0003);
		if (made.status) {
			call.fail(made.status == 0xc0000034U ? 2 : 87, 0);
			return;
		}
		call.ret(made.value);
	});
	// The interlocked operations act on one 32-bit word of the guest. Guest threads take turns, so the host needs no atomics of its own.
	registry.add("InterlockedIncrement", 1, [](ApiCall &call) {
		const auto value = call.load<int32_t>(call[0]) + 1;
		call.store<int32_t>(call[0], value);
		call.ret(uint32_t(value));
	});
	registry.add("InterlockedDecrement", 1, [](ApiCall &call) {
		const auto value = call.load<int32_t>(call[0]) - 1;
		call.store<int32_t>(call[0], value);
		call.ret(uint32_t(value));
	});
	registry.add("InterlockedExchange", 2, [](ApiCall &call) {
		const auto old = call.load<uint32_t>(call[0]);
		call.store<uint32_t>(call[0], call.u32(1));
		call.ret(old);
	});
	registry.add("InterlockedExchangeAdd", 2, [](ApiCall &call) {
		const auto old = call.load<uint32_t>(call[0]);
		call.store<uint32_t>(call[0], old + call.u32(1));
		call.ret(old);
	});
	registry.add("InterlockedCompareExchange", 3, [](ApiCall &call) {
		const auto old = call.load<uint32_t>(call[0]);
		if (old == call.u32(2))
			call.store<uint32_t>(call[0], call.u32(1));
		call.ret(old);
	});
	// A 64-bit operand is two words on the stack of a 32-bit program, so the value is put together from them.
	registry.add("InterlockedCompareExchange64", 5, [](ApiCall &call) {
		const bool narrow = call.pointer_width() == 4;
		const uint64_t exchange = narrow ? (call[1] & 0xffffffffULL) | call[2] << 32 : call[1];
		const uint64_t comparand = narrow ? (call[3] & 0xffffffffULL) | call[4] << 32 : call[2];
		const auto old = call.load<uint64_t>(call[0]);
		if (old == comparand)
			call.store<uint64_t>(call[0], exchange);
		call.ret(old);
	});
	// Mutexes and semaphores are kernel objects with optional names shared inside the process.
	auto names = std::make_shared<std::map<std::u16string, std::shared_ptr<KernelObject>>>();
	const auto named = [names](ApiCall &call, uint64_t name_address, std::shared_ptr<KernelObject> fresh) -> std::pair<std::shared_ptr<KernelObject>, bool> {
		if (!name_address)
			return {fresh, false};
		auto name = call.wide(name_address, 259);
		for (auto &character : name)
			character = upper_case(character);
		const auto found = names->find(name);
		if (found != names->end())
			return {found->second, true};
		(*names)[name] = fresh;
		return {fresh, false};
	};
	registry.add("CreateMutexW", 3, [&objects, named](ApiCall &call) {
		auto mutex = std::make_shared<MutexObject>();
		const auto [object, existed] = named(call, call[2], mutex);
		if (call.u32(1) && !existed)
			std::static_pointer_cast<MutexObject>(object)->consume(1);
		const auto made = objects.add_object(object);
		if (made.status) {
			call.fail(8);
			return;
		}
		call.set_last_error(existed ? 183 : 0);
		call.ret(made.value);
	});
	registry.add("CreateMutexExW", 4, [&objects, named](ApiCall &call) {
		auto mutex = std::make_shared<MutexObject>();
		const auto [object, existed] = named(call, call[1], mutex);
		const auto made = objects.add_object(object);
		if (made.status) {
			call.fail(8);
			return;
		}
		call.set_last_error(existed ? 183 : 0);
		call.ret(made.value);
	});
	registry.add("OpenMutexW", 3, [&objects, names](ApiCall &call) {
		auto name = call.wide(call[2], 259);
		for (auto &character : name)
			character = upper_case(character);
		const auto found = names->find(name);
		if (found == names->end() || !std::dynamic_pointer_cast<MutexObject>(found->second)) {
			call.fail(2);
			return;
		}
		call.ret(objects.add_object(found->second).value);
	});
	registry.add("ReleaseMutex", 1, [&objects, &threads](ApiCall &call) {
		const auto mutex = objects.object_as<MutexObject>(call[0]);
		if (!mutex) {
			call.fail(6);
			return;
		}
		if (mutex->owner != threads.current_id() || mutex->recursion <= 0) {
			call.fail(288);
			return;
		}
		if (--mutex->recursion == 0)
			mutex->owner = 0;
		call.ret(1);
	});
	const auto make_semaphore = [&objects, named](ApiCall &call, int64_t initial, int64_t maximum, uint64_t name) {
		if (maximum <= 0 || initial < 0 || initial > maximum) {
			call.fail(87);
			return;
		}
		auto semaphore = std::make_shared<SemaphoreObject>();
		semaphore->count = initial;
		semaphore->maximum = maximum;
		const auto [object, existed] = named(call, name, semaphore);
		const auto made = objects.add_object(object);
		if (made.status) {
			call.fail(8);
			return;
		}
		call.set_last_error(existed ? 183 : 0);
		call.ret(made.value);
	};
	registry.add("CreateSemaphoreW", 4, [make_semaphore](ApiCall &call) { make_semaphore(call, call.i32(1), call.i32(2), call[3]); });
	registry.add("CreateSemaphoreExW", 6, [make_semaphore](ApiCall &call) { make_semaphore(call, call.i32(1), call.i32(2), call[3]); });
	registry.add("ReleaseSemaphore", 3, [&objects](ApiCall &call) {
		const auto semaphore = objects.object_as<SemaphoreObject>(call[0]);
		const int32_t amount = call.i32(1);
		if (!semaphore) {
			call.fail(6);
			return;
		}
		if (amount <= 0 || semaphore->count + amount > semaphore->maximum) {
			call.fail(298);
			return;
		}
		if (call[2]) call.store<int32_t>(call[2], int32_t(semaphore->count));
		semaphore->count += amount;
		call.ret(1);
	});

	// Thread pool work items run on short-lived guest threads; waiting on them joins those threads.
	registry.add("CreateThreadpoolWork", 3, [&objects](ApiCall &call) {
		auto work = std::make_shared<WorkObject>();
		work->callback = call[0];
		work->parameter = call[1];
		const auto made = objects.add_object(work);
		call.ret(made.status ? 0 : made.value);
	});
	registry.add("SubmitThreadpoolWork", 1, [&objects, &threads, &context](ApiCall &call) {
		const auto work = objects.object_as<WorkObject>(call[0]);
		if (!work)
			return;
		// TP_CALLBACK_INSTANCE is opaque to callbacks; the work handle itself stands in for it.
		const auto instance = context.allocator.allocate(64);
		const auto thread = threads.create(work->callback, work->parameter, 1024 * 1024, false);
		thread->arguments = {instance, work->parameter, call[0]};
		work->running.push_back(thread);
	});
	registry.add("WaitForThreadpoolWorkCallbacks", 2, [&objects, &threads](ApiCall &call) {
		const auto work = objects.object_as<WorkObject>(call[0]);
		if (!work)
			return;
		threads.block([work] {
			return std::all_of(work->running.begin(), work->running.end(), [](const auto &thread) { return thread->state == GuestThread::State::done; });
		}, std::nullopt);
	});
	registry.add("CloseThreadpoolWork", 1, [&objects](ApiCall &call) { objects.close(call[0]); });
}

}

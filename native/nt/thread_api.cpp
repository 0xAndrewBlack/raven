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
	registry.add("ResumeThread", 1, [thread_from](ApiCall &call) {
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
	registry.add("SetThreadDescription", 2, [](ApiCall &call) { call.ret(0); });
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

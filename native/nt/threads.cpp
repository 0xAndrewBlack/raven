#include "threads.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>
#include <sys/mman.h>
#include <thread>

namespace raven {

namespace {

constexpr size_t host_stack_size = 1024 * 1024;

}

NativeThreads::NativeThreads(NativeProcess &process, NativeEnvironment &environment, NativeMemory &memory, NativeTLS &tls,
	std::chrono::steady_clock::time_point deadline)
	: process(process), environment(environment), memory(memory), tls(tls), deadline(deadline)
{
	auto main = std::make_shared<GuestThread>();
	main->id = 1;
	main->teb = environment.teb();
	main->state = GuestThread::State::running;
	main->main = true;
	threads.push_back(main);
	running = main.get();
}

NativeThreads::~NativeThreads()
{
	// Host frames of threads that never finished hold objects that only their unwinding releases; a failure here must not escape.
	try {
		unwind_all();
	} catch (...) {
	}
}

size_t NativeThreads::live() const
{
	return size_t(std::count_if(threads.begin(), threads.end(), [](const auto &thread) { return thread->state != GuestThread::State::done; }));
}

std::vector<uint64_t> NativeThreads::thread_blocks() const
{
	std::vector<uint64_t> result;
	for (const auto &thread : threads)
		if (thread->state != GuestThread::State::done && thread->teb)
			result.push_back(thread->teb);
	return result;
}

std::shared_ptr<GuestThread> NativeThreads::find(uint32_t id) const
{
	for (const auto &thread : threads)
		if (thread->id == id)
			return thread;
	return nullptr;
}

std::shared_ptr<GuestThread> NativeThreads::create(uint64_t start, uint64_t parameter, uint64_t stack_size, bool suspended)
{
	if (live() >= 256)
		throw std::runtime_error("native guest thread limit reached");
	auto thread = std::make_shared<GuestThread>();
	const uint64_t size = std::clamp<uint64_t>((stack_size + 0xffff) & ~uint64_t(0xffff), 256 * 1024, 64 * 1024 * 1024);
	// One unreadable page below the stack turns an overflow into a fault instead of silent corruption.
	const auto range = memory.allocate(0, size + 4096, 0x3000, 4);
	if (range.status)
		throw std::runtime_error("native guest thread stack allocation failed");
	memory.protect(range.address, 4096, 1);
	thread->stack_low = range.address + 4096;
	thread->stack_high = range.address + size + 4096;
	thread->id = next_id;
	next_id += 4;
	thread->teb = environment.create_thread_block(thread->stack_high, thread->stack_low, thread->id);
	tls.create_thread(thread->teb);
	thread->start = start;
	thread->parameter = parameter;
	thread->snapshot = process.new_thread(thread->stack_high - 64, thread->teb);
	thread->suspend_count = suspended ? 1 : 0;
	thread->host_stack = std::make_unique<char[]>(host_stack_size);
	getcontext(&thread->context);
	thread->context.uc_stack.ss_sp = thread->host_stack.get();
	thread->context.uc_stack.ss_size = host_stack_size;
	thread->context.uc_link = nullptr;
	const auto address = reinterpret_cast<uintptr_t>(thread.get());
	makecontext(&thread->context, reinterpret_cast<void (*)()>(&NativeThreads::trampoline), 2, unsigned(address & 0xffffffffU), unsigned(address >> 32));
	thread->state = GuestThread::State::ready;
	threads.push_back(thread);
	return thread;
}

namespace {
NativeThreads *active_scheduler = nullptr;
}

void NativeThreads::trampoline(unsigned low, unsigned high)
{
	auto *thread = reinterpret_cast<GuestThread *>(uintptr_t(low) | uintptr_t(high) << 32);
	active_scheduler->thread_main(*thread);
}

void NativeThreads::thread_main(GuestThread &thread)
{
	uint32_t code = 0;
	try {
		if (thread.unwinding)
			throw ThreadExit{0};
		if (notifier)
			notifier(2);
		const std::vector<uint64_t> arguments = thread.arguments.empty() ? std::vector<uint64_t>{thread.parameter} : thread.arguments;
		const auto result = run(thread.start, arguments);
		if (result.stop != NativeStop::returned)
			throw result;
		code = uint32_t(result.value);
		if (notifier)
			notifier(3);
	} catch (const ThreadExit &exit) {
		code = exit.code;
	} catch (...) {
		pending = std::current_exception();
	}
	finish(thread, code);
	// A finished coroutine never resumes; hand the processor on and stay parked. What the scheduler throws here (the process deadline)
	// is for the main thread, which receives it through the pending exception.
	for (;;) {
		try {
			schedule();
		} catch (...) {
			pending = std::current_exception();
			// The main thread rethrows it from its own switch; hand the processor to it directly.
			auto &main = *threads.front();
			if (main.state != GuestThread::State::done && &main != running)
				switch_to(main);
		}
	}
}

void NativeThreads::finish(GuestThread &thread, uint32_t code)
{
	thread.exit_code = code;
	thread.state = GuestThread::State::done;
	thread.ready = nullptr;
}

void NativeThreads::release_resources(GuestThread &thread)
{
	if (thread.main || !thread.teb)
		return;
	tls.release_thread(thread.teb);
	environment.release_thread_block(thread.teb);
	thread.teb = 0;
	if (thread.stack_low) {
		memory.free(thread.stack_low - 4096, 0, 0x8000);
		thread.stack_low = thread.stack_high = 0;
	}
}

void NativeThreads::reap()
{
	for (auto &thread : threads)
		if (thread->state == GuestThread::State::done && thread.get() != running && thread->host_stack) {
			thread->host_stack.reset();
			release_resources(*thread);
		}
}

std::shared_ptr<GuestThread> NativeThreads::pick(bool include_current)
{
	const auto now = std::chrono::steady_clock::now();
	const size_t count = threads.size();
	size_t start = 0;
	for (size_t index = 0; index < count; ++index)
		if (threads[index].get() == running)
			start = index;
	for (size_t step = 1; step <= count; ++step) {
		const auto &thread = threads[(start + step) % count];
		if (thread.get() == running && !include_current)
			continue;
		if (thread->state == GuestThread::State::done || thread->suspend_count > 0)
			continue;
		if (thread->state == GuestThread::State::ready)
			return thread;
		if (thread->state == GuestThread::State::waiting) {
			if ((thread->ready && thread->ready()) || (thread->wake && now >= *thread->wake) || !thread->apcs.empty() )
				return thread;
		}
	}
	return nullptr;
}

void NativeThreads::check_pending()
{
	if (!pending || !running->main)
		return;
	const auto exception = pending;
	pending = nullptr;
	// The error that ended another thread ends the process; the call this thread was waiting in will never complete.
	try {
		process.abandon_call();
	} catch (const std::runtime_error &) {
	}
	std::rethrow_exception(exception);
}

void NativeThreads::switch_to(GuestThread &next)
{
	if (&next == running)
		return;
	GuestThread &previous = *running;
	previous.snapshot = process.save_thread();
	process.load_thread(next.snapshot);
	environment.set_current(next.teb);
	running = &next;
	if (previous.state == GuestThread::State::running)
		previous.state = GuestThread::State::ready;
	next.state = GuestThread::State::running;
	active_scheduler = this;
	swapcontext(&previous.context, &next.context);
	// Resumed: whoever switched back already loaded this thread's guest state.
	reap();
	if (running->unwinding && !running->main)
		throw ThreadExit{0};
	check_pending();
}

void NativeThreads::schedule()
{
	for (;;) {
		if (!tearing_down && std::chrono::steady_clock::now() >= deadline)
			throw NativeResult{NativeStop::timeout, 0, 0, 0};
		// A pending exception from a finished thread is for the main thread alone.
		if (pending && !running->main) {
			auto &main = *threads.front();
			if (main.state != GuestThread::State::done) {
				switch_to(main);
				continue;
			}
		}
		// The choice is held as a plain pointer: the frame of a thread that is parked for good is freed without unwinding, and an owning
		// reference kept in it would never be released. The thread list owns every thread.
		if (GuestThread *next = pick(true).get()) {
			if (next == running) {
				running->state = GuestThread::State::running;
				return;
			}
			switch_to(*next);
			if (running->state == GuestThread::State::done)
				continue;
			return;
		}
		// Nothing can run: wait for the earliest timeout, letting the host deliver outside events meanwhile.
		auto wake = std::chrono::steady_clock::time_point::max();
		bool any = false;
		for (const auto &thread : threads)
			if (thread->state == GuestThread::State::waiting && thread->wake && thread->suspend_count == 0) {
				wake = std::min(wake, *thread->wake);
				any = true;
			}
		const auto now = std::chrono::steady_clock::now();
		if (!any && !poll)
			throw std::runtime_error("native guest threads deadlocked: every thread waits without a timeout");
		const auto limit = std::min(wake, deadline);
		auto slice = std::chrono::duration_cast<std::chrono::milliseconds>(limit > now ? limit - now : std::chrono::nanoseconds(0));
		slice = std::min(slice, std::chrono::milliseconds(20));
		if (poll)
			poll(slice);
		else if (slice.count() > 0)
			std::this_thread::sleep_for(slice);
	}
}

bool NativeThreads::block(std::function<bool()> ready, std::optional<std::chrono::steady_clock::time_point> wake)
{
	if (ready())
		return true;
	if (wake && std::chrono::steady_clock::now() >= *wake)
		return false;
	auto &me = *running;
	me.ready = std::move(ready);
	me.wake = wake;
	me.state = GuestThread::State::waiting;
	schedule();
	const bool satisfied = me.ready && me.ready();
	me.ready = nullptr;
	me.wake.reset();
	me.state = GuestThread::State::running;
	return satisfied;
}

bool NativeThreads::yield()
{
	GuestThread *next = pick(false).get();
	if (!next)
		return false;
	running->state = GuestThread::State::ready;
	switch_to(*next);
	running->state = GuestThread::State::running;
	return true;
}

void NativeThreads::exit_current(uint32_t code)
{
	throw ThreadExit{code};
}

void NativeThreads::terminate(const std::shared_ptr<GuestThread> &thread, uint32_t code)
{
	if (thread.get() == running)
		exit_current(code);
	finish(*thread, code);
}

void NativeThreads::unwind_all()
{
	if (!running || !running->main)
		return;
	tearing_down = true;
	std::vector<std::shared_ptr<GuestThread>> remaining;
	for (const auto &thread : threads)
		if (!thread->main && thread->state != GuestThread::State::done) {
			thread->unwinding = true;
			thread->ready = nullptr;
			thread->wake.reset();
			thread->apcs.clear();
			thread->suspend_count = 0;
			thread->state = GuestThread::State::ready;
			remaining.push_back(thread);
		}
	for (const auto &thread : remaining)
		if (thread->state != GuestThread::State::done)
			switch_to(*thread);
	pending = nullptr;
}

void NativeThreads::resume(GuestThread &thread)
{
	if (thread.suspend_count > 0)
		--thread.suspend_count;
}

}

#include "native_cpu.h"
#include <cstddef>

#include <algorithm>
#include <cinttypes>
#include <fstream>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <sstream>
#include <elf.h>
#include <fcntl.h>
#include <functional>
#include <csignal>
#include <ctime>
#include <mutex>
#include <map>
#include <set>
#include <optional>
#include <signal.h>
#include <stdexcept>
#include <sys/mman.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <execinfo.h>
#include <unistd.h>

namespace raven {

// The API the runtime handled last, named when a call is left without its answer.
extern const char *api_in_progress;

// The registers of the stopped guest, read once per stop: serving one call read them several times, and each read is a system call.
// Anything that can change them (writing them, resuming the guest, the guest stopping again) drops the copy.
static thread_local pid_t registers_of = -1;
static thread_local user_regs_struct cached_registers;

static void forget_registers()
{
	registers_of = -1;
}

static void trace(enum __ptrace_request operation, pid_t child, void *data = nullptr)
{
	if (operation == PTRACE_GETREGS && registers_of == child) {
		std::memcpy(data, &cached_registers, sizeof cached_registers);
		return;
	}
	if (operation != PTRACE_GETREGS && operation != PTRACE_GETSIGINFO && operation != PTRACE_GETREGSET && operation != PTRACE_PEEKTEXT &&
		operation != PTRACE_PEEKDATA && operation != PTRACE_PEEKUSER)
		forget_registers();
	if (ptrace(operation, child, nullptr, data) == -1) {
		const int failure = errno;
		if (std::getenv("RAVEN_BACKTRACE")) {
			void *frames[32];
			std::fprintf(stderr, "ptrace request %d on %d failed: %s\n", int(operation), int(child), std::strerror(failure));
			backtrace_symbols_fd(frames, backtrace(frames, 32), 2);
		}
		throw std::runtime_error("native ptrace: " + std::string(std::strerror(failure)));
	}
	if (operation == PTRACE_GETREGS) {
		std::memcpy(&cached_registers, data, sizeof cached_registers);
		registers_of = child;
	}
}

class NativeChild {
public:
	NativeChild(std::span<const int> image_fds, const std::string &bootstrap, std::chrono::milliseconds timeout);
	~NativeChild();
	NativeChild(const NativeChild &) = delete;
	NativeChild &operator=(const NativeChild &) = delete;
	pid_t pid = -1;
	uint64_t gate = 0;
	// `served` is polled while the guest runs: calls the guest makes without stopping are answered there.
	int wait(const std::function<bool()> *served = nullptr);
	uint64_t syscall(uint64_t number, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0,
		uint64_t a4 = 0, uint64_t a5 = 0, uint64_t a6 = 0);
	void stop();
	void set_timeout(std::chrono::milliseconds timeout);
	// While a slice is set, wait() returns -2 once it has passed without the guest stopping.
	void set_slice(std::chrono::steady_clock::duration slice) { slice_end = std::chrono::steady_clock::now() + slice; }
	// Sets a slice that ends at `end` unless one is already running.
	void ensure_slice(std::chrono::steady_clock::time_point end)
	{
		if (!slice_end)
			slice_end = end;
	}
	void clear_slice() { slice_end.reset(); }

private:
	std::chrono::steady_clock::time_point deadline;
	std::optional<std::chrono::steady_clock::time_point> slice_end;
};

NativeChild::NativeChild(std::span<const int> image_fds, const std::string &bootstrap, std::chrono::milliseconds timeout)
	: deadline(std::chrono::steady_clock::now() + timeout)
{
	const char *path = bootstrap.c_str();
	pid = fork();
	if (pid == -1)
		throw std::runtime_error("cannot fork native guest");
	if (pid == 0) {
		for (int fd : image_fds) {
			if (fcntl(fd, F_SETFD, 0) == -1)
				_exit(126);
		}
		if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) == -1)
			_exit(126);
		execl(path, path, static_cast<char *>(nullptr));
		_exit(127);
	}
	try {
		int status = wait();
		if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
			throw std::runtime_error("native bootstrap did not stop after exec");
		trace(PTRACE_SETOPTIONS, pid, reinterpret_cast<void *>(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD));
		trace(PTRACE_CONT, pid);
		status = wait();
		if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
			throw std::runtime_error("native bootstrap did not reach setup trap");
		user_regs_struct registers{};
		trace(PTRACE_GETREGS, pid, &registers);
		gate = registers.rip - 1;
		errno = 0;
		const long code = ptrace(PTRACE_PEEKTEXT, pid, reinterpret_cast<void *>(gate), nullptr);
		if ((code == -1 && errno != 0) || (static_cast<uint64_t>(code) & 0xffffffff) != 0xcc050fcc)
			throw std::runtime_error("native bootstrap syscall gate is invalid");
	} catch (...) {
		stop();
		throw;
	}
}

NativeChild::~NativeChild()
{
	stop();
}

void NativeChild::set_timeout(std::chrono::milliseconds timeout)
{
	if (timeout.count() <= 0)
		throw std::runtime_error("native execution requires a positive timeout");
	deadline = std::chrono::steady_clock::now() + timeout;
}

void NativeChild::stop()
{
	if (pid == -1)
		return;
	kill(pid, SIGKILL);
	int status = 0;
	while (waitpid(pid, &status, 0) == -1 && errno == EINTR) {}
	forget_registers();
	pid = -1;
}

// The tracer thread's wake-up while it is blocked waiting for the guest: a one-shot timer that interrupts waitpid with a signal whose
// handler does nothing. The timer is disarmed as soon as the wait returns and the signal is never blocked, so it cannot stay pending and
// interrupt anything else.
static void interrupt_wait(int) {}

static timer_t wait_timer()
{
	static thread_local std::optional<timer_t> timer;
	if (timer)
		return *timer;
	static std::once_flag installed;
	std::call_once(installed, [] {
		struct sigaction action{};
		action.sa_handler = interrupt_wait;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGRTMIN + 5, &action, nullptr) == -1)
			throw std::runtime_error("cannot install the guest wait alarm");
	});
	sigevent event{};
	event.sigev_notify = SIGEV_THREAD_ID;
	event.sigev_signo = SIGRTMIN + 5;
	event._sigev_un._tid = gettid();
	timer_t created;
	if (timer_create(CLOCK_MONOTONIC, &event, &created) == -1)
		throw std::runtime_error("cannot create the guest wait alarm");
	timer = created;
	return created;
}

int NativeChild::wait(const std::function<bool()> *served)
{
	// Guest code usually reaches its next trap within microseconds, so it is polled first; a guest that runs longer is waited for
	// asleep, which leaves the processor to it. A served call made meanwhile ends in a trap, which wakes the wait.
	unsigned polls = 0;
	for (;;) {
		// A guest that is being served keeps running, so it is as busy as one that just started; it never stops for its calls, so its
		// slice is looked at after each of them.
		if (served && (*served)()) {
			polls = 0;
			if (slice_end && std::chrono::steady_clock::now() >= *slice_end)
				return -2;
			continue;
		}
		int status = 0;
		pid_t result = waitpid(pid, &status, WNOHANG);
		if (result == 0 && ++polls >= 200) {
			const auto now = std::chrono::steady_clock::now();
			if (slice_end && now >= *slice_end)
				return -2;
			if (now >= deadline)
				return -1;
			const auto until = slice_end ? std::min(*slice_end, deadline) : deadline;
			const auto left = std::chrono::duration_cast<std::chrono::nanoseconds>(until - now).count();
			itimerspec alarm{};
			alarm.it_value.tv_sec = left / 1000000000;
			alarm.it_value.tv_nsec = left % 1000000000;
			const timer_t timer = wait_timer();
			timer_settime(timer, 0, &alarm, nullptr);
			result = waitpid(pid, &status, 0);
			const itimerspec off{};
			timer_settime(timer, 0, &off, nullptr);
		}
		if (result == pid) {
			forget_registers();
			if (WIFEXITED(status) || WIFSIGNALED(status)) {
				if (std::getenv("RAVEN_TRACE_API"))
					std::cerr << "raven: native guest " << (WIFSIGNALED(status) ? "killed by signal " + std::to_string(WTERMSIG(status)) : "exited with " + std::to_string(WEXITSTATUS(status))) << '\n';
				pid = -1;
			}
			return status;
		}
		if (result == -1 && errno != EINTR)
			throw std::runtime_error("cannot wait for native guest");
	}
}

uint64_t NativeChild::syscall(uint64_t number, uint64_t a1, uint64_t a2, uint64_t a3,
	uint64_t a4, uint64_t a5, uint64_t a6)
{
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, pid, &registers);
	registers.rip = gate + 1;
	// The gate is a 64-bit SYSCALL; a compatibility-mode guest is switched out only for this instruction.
	registers.cs = 0x33;
	registers.ss = 0x2b;
	registers.rax = number;
	registers.orig_rax = uint64_t(-1);
	registers.rdi = a1;
	registers.rsi = a2;
	registers.rdx = a3;
	registers.r10 = a4;
	registers.r8 = a5;
	registers.r9 = a6;
	trace(PTRACE_SETREGS, pid, &registers);
	// PTRACE_CONT executes only this owned gate, never guest code. A slice left over from the last resume must not end this wait.
	clear_slice();
	trace(PTRACE_CONT, pid);
	const int status = wait();
	if (status == -1 || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
		std::ostringstream detail;
		detail << "native syscall did not reach its trap (wait status 0x" << std::hex << status << ')';
		throw std::runtime_error(detail.str());
	}
	trace(PTRACE_GETREGS, pid, &registers);
	if (registers.rip != gate + 4)
		throw std::runtime_error("native syscall stopped outside its gate");
	if (registers.rax >= uint64_t(-4095))
		throw std::runtime_error("native syscall: " + std::string(std::strerror(static_cast<int>(-registers.rax))));
	return registers.rax;
}

struct NativeProcess::State {
	std::unique_ptr<NativeChild> child;
	// The guest's own mappings by start address; they never overlap. A program such as a browser makes thousands of them, and every
	// read, write and protection change looks one up.
	std::map<uint64_t, ImageMapping> mappings;
	std::vector<std::pair<uint64_t, uint64_t>> allocations;
	std::vector<std::pair<uint64_t, uint64_t>> image_allocations;
	std::map<uint64_t, uint32_t> api_traps;
	// 64-bit API breakpoints followed by RET: their calls return through it, without the runtime popping the return address.
	std::set<uint64_t> returning_traps;
	NativeMode mode = NativeMode::x64;
	uint64_t return_gate = 0;
	uint32_t fs_selector = 0;
	uint32_t ldt_entries = 1;
	// A translated call: arguments and floating point arguments supplied by an adapter, and the result it left.
	// Time slicing of guest threads: how long one may run before another gets a turn, whether another could use one, and the hand-over.
	std::chrono::milliseconds slice{0};
	std::chrono::steady_clock::time_point slice_started = std::chrono::steady_clock::now();
	std::function<bool()> slice_wanted;
	std::function<void()> slice_yield;
	std::optional<std::vector<uint64_t>> translated_words;
	// How deep in guest callbacks the translated call was made: a callback the handler starts makes real calls of its own.
	size_t translated_depth = 0;
	std::array<uint64_t, 4> translated_floats{};
	uint64_t translated_result = 0;
	uint64_t fs_base = 0;
	uint32_t pending_cleanup = 0;
	std::vector<NativeContext> callbacks;
	std::vector<uint32_t> callback_cleanups;
	uint64_t stack_top = 0;
	// The first thread keeps its stack for the life of the process; other threads borrow stack_top while they run.
	uint64_t initial_stack_top = 0;
	bool stopped = true;
	bool active_call = false;
	bool awaiting_api = false;
	bool awaiting_syscall = false;
	// The guest's own system calls stop it through a seccomp filter instead of system call emulation: only those of the runtime's gate
	// run, every other one stops the guest before it runs, as emulation did.
	bool seccomp = false;
	bool debug_print_fault = false;
	size_t steps_left = 0;
	std::function<void(uint64_t)> step_sink;
	// Calls served while the guest runs: the block the guest's stubs fill, the handler, and whether one is being served now.
	uint64_t *served_block = nullptr;
	// Where the served stubs start, in order, and how many bytes each covers before its fallback trap.
	std::vector<uint64_t> served_stubs;
	size_t served_stub_size = 0;
	// The breakpoint a stub reaches when it has waited too long for its answer.
	size_t served_wait_offset = 0;
	std::function<void(uint64_t)> served_handler;
	std::function<void()> resume_hook;
	std::function<bool()> poll_served;
	bool serving = false;
	// Diagnostics: where the guest is found running, every sample_period.
	std::chrono::milliseconds sample_period{0};
	std::function<void(uint64_t)> sampler;
	// Where the stack arguments of the call being served start; they are read only when a handler asks for them.
	uint64_t served_stack = 0;
	void require_stopped() const;
	bool covers(uint64_t address, size_t size, int protection) const;
	uint64_t limit() const { return mode == NativeMode::x86 ? 0x100000000ULL : 0x800000000000ULL; }
};

void NativeProcess::State::require_stopped() const
{
	if (!child || child->pid == -1)
		throw std::runtime_error("native process is not stopped and alive (the guest process is gone)");
	if (!stopped && !serving)
		throw std::runtime_error("native process is not stopped and alive (it is running or a resume ended without a stop)");
}

bool NativeProcess::State::covers(uint64_t address, size_t size, int protection) const
{
	if (size > UINT64_MAX - address)
		return false;
	const uint64_t end = address + size;
	while (address < end) {
		auto found = mappings.upper_bound(address);
		if (found == mappings.begin())
			return false;
		const auto &mapping = std::prev(found)->second;
		if (address - mapping.address >= mapping.size || (mapping.protection & protection) != protection)
			return false;
		address = std::min(end, mapping.address + mapping.size);
	}
	return true;
}

NativeProcess::NativeProcess(std::span<LoadedImage *const> images, const std::string &bootstrap,
	std::chrono::milliseconds setup_timeout, NativeMode mode) : state(std::make_unique<State>())
{
	if (setup_timeout.count() <= 0)
		throw std::runtime_error("native execution requires a positive timeout");
	state->mode = mode;
	std::vector<int> descriptors;
	for (auto *mapped_image : images) {
		if (!mapped_image)
			throw std::runtime_error("null native image mapping");
		if (mapped_image->data().size() > state->limit() || mapped_image->base() > state->limit() - mapped_image->data().size())
			throw std::runtime_error("native image does not fit the guest address space");
		descriptors.push_back(mapped_image->descriptor());
	}
	state->child = std::make_unique<NativeChild>(descriptors, bootstrap, setup_timeout);
	auto &child = *state->child;
	for (auto *mapped_image : images) {
		const auto mapped = child.syscall(SYS_mmap, mapped_image->base(), mapped_image->data().size(), PROT_NONE,
			MAP_SHARED | MAP_FIXED_NOREPLACE, static_cast<uint64_t>(mapped_image->descriptor()));
		if (mapped != mapped_image->base())
			throw std::runtime_error("host does not support exact non-replacing guest mappings");
		for (const auto &mapping : mapped_image->mappings()) {
			child.syscall(SYS_mprotect, mapping.address, mapping.size, static_cast<uint64_t>(mapping.protection));
			state->mappings.insert_or_assign(mapping.address, mapping);
		}
	}
	const uint64_t stack_size = 1024 * 1024;
	const uint64_t low_flag = mode == NativeMode::x86 ? MAP_32BIT : 0;
	const auto stack = child.syscall(SYS_mmap, 0, stack_size + 8192, PROT_NONE,
		MAP_PRIVATE | MAP_ANONYMOUS | low_flag, uint64_t(-1));
	if (stack + stack_size + 8192 > state->limit())
		throw std::runtime_error("host placed the native stack outside the guest address space");
	child.syscall(SYS_mprotect, stack + 4096, stack_size, PROT_READ | PROT_WRITE);
	state->mappings.insert_or_assign(stack + 4096, ImageMapping{stack + 4096, stack_size, 0, PROT_READ | PROT_WRITE});
	state->stack_top = stack + 4096 + stack_size;
	state->initial_stack_top = state->stack_top;
	if (mode == NativeMode::x86) {
		// 32-bit return addresses cannot name the 64-bit bootstrap gate, so calls return through an INT3 page below 4 GiB.
		const auto page = child.syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, uint64_t(-1));
		if (page + 4096 > state->limit())
			throw std::runtime_error("host placed the native return gate outside the guest address space");
		state->mappings.insert_or_assign(page, ImageMapping{page, 4096, 0, PROT_READ | PROT_WRITE});
		write_memory(page, std::vector<uint8_t>{0xcc});
		child.syscall(SYS_mprotect, page, 4096, PROT_READ | PROT_EXEC);
		state->mappings.at(page).protection = PROT_READ | PROT_EXEC;
		state->return_gate = page;
	}
	if (mode == NativeMode::x64 && std::getenv("RAVEN_SECCOMP"))
		install_seccomp();
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, child.pid, &registers);
	registers.rax = registers.rbx = registers.rcx = registers.rdx = registers.rsi = registers.rdi = registers.rbp = 0;
	registers.r8 = registers.r9 = registers.r10 = registers.r11 = registers.r12 = registers.r13 = registers.r14 = registers.r15 = 0;
	registers.fs_base = registers.gs_base = 0;
	registers.orig_rax = uint64_t(-1);
	registers.eflags = 0x202;
	trace(PTRACE_SETREGS, child.pid, &registers);
	context();
}

NativeProcess::~NativeProcess() = default;

void NativeProcess::install_seccomp()
{
	auto &child = *state->child;
	// The filter: an x86-64 system call whose instruction pointer is the one after the gate's SYSCALL runs; any other stops the guest
	// for the runtime (SECCOMP_RET_TRACE), which then skips it as it skipped emulated ones.
	const uint64_t after_gate = child.gate + 3;
	const sock_filter program[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 0, 4),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, instruction_pointer)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, uint32_t(after_gate), 0, 2),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(seccomp_data, instruction_pointer) + 4),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, uint32_t(after_gate >> 32), 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_TRACE),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	const auto page = child.syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, uint64_t(-1));
	std::vector<uint8_t> bytes(sizeof program + 16);
	std::memcpy(bytes.data() + 16, program, sizeof program);
	const uint16_t count = sizeof program / sizeof program[0];
	const uint64_t filter = page + 16;
	std::memcpy(bytes.data(), &count, 2);
	std::memcpy(bytes.data() + 8, &filter, 8);
	const iovec local{bytes.data(), bytes.size()};
	const iovec remote{reinterpret_cast<void *>(page), bytes.size()};
	if (process_vm_writev(child.pid, &local, 1, &remote, 1, 0) != ssize_t(bytes.size()))
		throw std::runtime_error("cannot write the native seccomp filter");
	child.syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	child.syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, page);
	child.syscall(SYS_munmap, page, 4096);
	trace(PTRACE_SETOPTIONS, child.pid, reinterpret_cast<void *>(PTRACE_O_EXITKILL | PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACESECCOMP));
	state->seccomp = true;
}

NativeContext NativeProcess::context() const
{
	state->require_stopped();
	NativeContext result{};
	trace(PTRACE_GETREGS, state->child->pid, &result.registers);
	// The size of the extended state is the processor's, the same for every read: it is learned once, and later reads take a buffer of
	// exactly that size instead of zeroing 64 KiB for each thread switch.
	static size_t xstate_size = 0;
	result.xstate.resize(xstate_size ? xstate_size : 65536);
	iovec buffer{result.xstate.data(), result.xstate.size()};
	if (ptrace(PTRACE_GETREGSET, state->child->pid, reinterpret_cast<void *>(NT_X86_XSTATE), &buffer) == -1)
		throw std::runtime_error("host cannot expose native XSTATE");
	if (buffer.iov_len < 512 || (xstate_size ? buffer.iov_len != xstate_size : buffer.iov_len >= result.xstate.size()))
		throw std::runtime_error("invalid native XSTATE size");
	xstate_size = buffer.iov_len;
	result.xstate.resize(buffer.iov_len);
	return result;
}

void NativeProcess::set_context(const NativeContext &context)
{
	state->require_stopped();
	// The general registers go first: if the extended state is then refused, they are put back, and nothing has changed.
	user_regs_struct previous{};
	trace(PTRACE_GETREGS, state->child->pid, &previous);
	trace(PTRACE_SETREGS, state->child->pid, const_cast<user_regs_struct *>(&context.registers));
	iovec buffer{const_cast<uint8_t *>(context.xstate.data()), context.xstate.size()};
	if (ptrace(PTRACE_SETREGSET, state->child->pid, reinterpret_cast<void *>(NT_X86_XSTATE), &buffer) == -1 || buffer.iov_len != context.xstate.size()) {
		try {
			trace(PTRACE_SETREGS, state->child->pid, &previous);
		} catch (...) {
			state->child->stop();
		}
		throw std::runtime_error("cannot restore native XSTATE");
	}
}

std::vector<uint8_t> NativeProcess::read_memory(uint64_t address, size_t size) const
{
	state->require_stopped();
	if (!state->covers(address, size, PROT_READ))
		throw std::runtime_error("native read exceeds readable guest memory" + (std::getenv("RAVEN_TRACE_API") ? " at " + std::to_string(address) + "+" + std::to_string(size) : std::string()));
	std::vector<uint8_t> result(size);
	for (size_t offset = 0; offset < size;) {
		const iovec local{result.data() + offset, size - offset};
		const iovec remote{reinterpret_cast<void *>(address + offset), size - offset};
		const auto copied = process_vm_readv(state->child->pid, &local, 1, &remote, 1, 0);
		if (copied < 0 && errno == EINTR) continue;
		if (copied <= 0)
			throw std::runtime_error("cannot read native guest memory");
		offset += static_cast<size_t>(copied);
	}
	return result;
}

void NativeProcess::write_memory(uint64_t address, std::span<const uint8_t> bytes)
{
	validate_write_memory(address,bytes.size());
	for (size_t offset = 0; offset < bytes.size();) {
		const iovec local{const_cast<uint8_t *>(bytes.data() + offset), bytes.size() - offset};
		const iovec remote{reinterpret_cast<void *>(address + offset), bytes.size() - offset};
		const auto copied = process_vm_writev(state->child->pid, &local, 1, &remote, 1, 0);
		if (copied < 0 && errno == EINTR) continue;
		if (copied <= 0)
			throw std::runtime_error("cannot write native guest memory");
		offset += static_cast<size_t>(copied);
	}
}

void NativeProcess::validate_write_memory(uint64_t address,size_t size) const
{
	state->require_stopped();
	if (!state->covers(address,size,PROT_WRITE)) throw std::runtime_error("native write exceeds writable guest memory");
}

uint64_t NativeProcess::memory_syscall(uint64_t number, uint64_t a1, uint64_t a2,
	uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6)
{
	state->require_stopped();
	// A Linux system call leaves the extended processor state alone, so only the general registers the gate uses are kept.
	auto &child = *state->child;
	user_regs_struct saved{};
	trace(PTRACE_GETREGS, child.pid, &saved);
	child.set_timeout(std::chrono::seconds(2));
	uint64_t result = 0;
	try {
		result = child.syscall(number, a1, a2, a3, a4, a5, a6);
	} catch (...) {
		try {
			user_regs_struct where{};
			if (child.pid != -1)
				trace(PTRACE_GETREGS, child.pid, &where);
			if (child.pid == -1 || where.rip != child.gate + 4)
				throw std::runtime_error("native memory operation lost its gate");
			trace(PTRACE_SETREGS, child.pid, &saved);
		} catch (...) {
			child.stop();
			throw;
		}
		throw;
	}
	try {
		trace(PTRACE_SETREGS, child.pid, &saved);
	} catch (...) {
		child.stop();
		throw;
	}
	return result;
}

static void memory_range(uint64_t address, size_t size, int protection, uint64_t limit)
{
	if (!size || size % 4096 || size > (uint64_t(1) << 42) || address % 4096 ||
		address >= limit || size > limit - address || (protection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)))
		throw std::runtime_error("invalid native memory range or protection");
}

// MAP_32BIT only reaches the 1 GiB window that also holds the images, so 32-bit allocations take the lowest free 64 KiB aligned gap
// of the child's own address space and are then mapped there without replacing anything.
static uint64_t low_gap(pid_t pid, uint64_t size, uint64_t limit)
{
	std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
	constexpr uint64_t granularity = 0x10000;
	uint64_t candidate = granularity;
	std::string line;
	while (std::getline(maps, line)) {
		const auto dash = line.find('-');
		const uint64_t start = std::stoull(line.substr(0, dash), nullptr, 16);
		const uint64_t end = std::stoull(line.substr(dash + 1), nullptr, 16);
		if (start >= limit)
			break;
		if (start >= candidate && start - candidate >= size)
			return candidate;
		candidate = std::max(candidate, (end + granularity - 1) & ~(granularity - 1));
	}
	return candidate < limit && limit - candidate >= size ? candidate : 0;
}

uint64_t NativeProcess::map_memory(size_t size, int protection, uint64_t address)
{
	state->require_stopped();
	memory_range(address, size, protection, state->limit());
	state->allocations.reserve(state->allocations.size() + 1);
	const auto hint = address ? address : state->mode == NativeMode::x86 ? low_gap(state->child->pid, size, state->limit()) : 0;
	const auto mapped = memory_syscall(SYS_mmap, hint, size, static_cast<uint64_t>(protection),
		MAP_PRIVATE | MAP_ANONYMOUS | (protection == PROT_NONE ? MAP_NORESERVE : 0) | (hint ? MAP_FIXED_NOREPLACE : 0), uint64_t(-1));
	if ((address && mapped != address) || mapped >= state->limit() || size > state->limit() - mapped) {
		state->child->stop();
		throw std::runtime_error("host returned an invalid native allocation address");
	}
	state->mappings.insert_or_assign(mapped, ImageMapping{mapped, size, 0, protection});
	state->allocations.emplace_back(mapped, size);
	return mapped;
}

uint64_t NativeProcess::map_shared(int descriptor, size_t size, uint64_t offset)
{
	state->require_stopped();
	memory_range(0, size, PROT_READ | PROT_WRITE, state->limit());
	state->allocations.reserve(state->allocations.size() + 1);
	const auto path = "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(descriptor);
	std::vector<uint8_t> name(path.begin(), path.end());
	name.push_back(0);
	const auto scratch = map_memory(4096, PROT_READ | PROT_WRITE);
	uint64_t guest_descriptor = uint64_t(-1);
	try {
		write_memory(scratch, name);
		// Reopen only the host-owned memfd; guest code never executes the Linux syscall.
		guest_descriptor = memory_syscall(SYS_openat, uint64_t(AT_FDCWD), scratch, O_RDWR | O_CLOEXEC);
		// Windows places views on the 64 KiB allocation granularity and programs round view addresses down to it, so a view starts on
		// such a boundary: a reservation one granule larger is made, the file is mapped over its aligned part and the slack is returned.
		constexpr uint64_t granularity = 0x10000;
		const auto hint = state->mode == NativeMode::x86 ? low_gap(state->child->pid, size + granularity, state->limit()) : 0;
		const auto reserved = memory_syscall(SYS_mmap, hint, size + granularity, PROT_NONE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | (hint ? MAP_FIXED_NOREPLACE : 0), uint64_t(-1), 0);
		if (reserved >= state->limit() || size + granularity > state->limit() - reserved) {
			state->child->stop();
			throw std::runtime_error("host returned an invalid shared mapping address");
		}
		const uint64_t aligned = (reserved + granularity - 1) & ~(granularity - 1);
		const auto mapped = memory_syscall(SYS_mmap, aligned, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, guest_descriptor, offset);
		if (mapped != aligned) {
			state->child->stop();
			throw std::runtime_error("host returned an invalid shared mapping address");
		}
		if (aligned > reserved)
			memory_syscall(SYS_munmap, reserved, aligned - reserved);
		if (reserved + size + granularity > aligned + size)
			memory_syscall(SYS_munmap, aligned + size, reserved + size + granularity - aligned - size);
		memory_syscall(SYS_close, guest_descriptor, 0);
		guest_descriptor = uint64_t(-1);
		unmap_memory(scratch);
		state->mappings.insert_or_assign(mapped, ImageMapping{mapped, size, 0, PROT_READ | PROT_WRITE});
		state->allocations.emplace_back(mapped, size);
		return mapped;
	} catch (...) {
		try {
			if (guest_descriptor != uint64_t(-1))
				memory_syscall(SYS_close, guest_descriptor, 0);
			unmap_memory(scratch);
		} catch (...) {
			state->child->stop();
		}
		throw;
	}
}

bool NativeProcess::has_protection(uint64_t address, size_t size, int protection) const
{
	const uint64_t end = address + size;
	while (address < end) {
		const auto after = state->mappings.upper_bound(address);
		if (after == state->mappings.begin())
			return false;
		const auto &mapping = std::prev(after)->second;
		if (address - mapping.address >= mapping.size || mapping.protection != protection)
			return false;
		address = mapping.address + mapping.size;
	}
	return true;
}

void NativeProcess::protect_memory(uint64_t address, size_t size, int protection)
{
	protect_range(address, size, protection, false);
}

void NativeProcess::protect_image(uint64_t address, size_t size, int protection)
{
	protect_range(address, size, protection, true);
}

void NativeProcess::protect_range(uint64_t address, size_t size, int protection, bool image)
{
	state->require_stopped();
	memory_range(address, size, protection, state->limit());
	const auto owned = std::find_if(state->allocations.begin(), state->allocations.end(), [&](const auto &allocation) {
		return address >= allocation.first && address - allocation.first < allocation.second &&
			size <= allocation.second - (address - allocation.first);
	});
	if (owned == state->allocations.end() && image) {
		// A program may also protect the pages of an image it was loaded from: they are accepted when mappings cover the whole range.
		uint64_t cursor = address;
		while (cursor < address + size) {
			const auto after = state->mappings.upper_bound(cursor);
			if (after == state->mappings.begin() || cursor - std::prev(after)->second.address >= std::prev(after)->second.size)
				throw std::runtime_error("native protection range is outside a dynamic allocation");
			cursor = std::prev(after)->second.address + std::prev(after)->second.size;
		}
	} else if (owned == state->allocations.end()) {
		throw std::runtime_error("native protection range is outside a dynamic allocation");
	}
	// Only the mappings the range touches are split; they are replaced once the guest's protection has changed.
	const uint64_t end = address + size;
	auto first_touched = state->mappings.upper_bound(address);
	if (first_touched != state->mappings.begin() && std::prev(first_touched)->second.address + std::prev(first_touched)->second.size > address)
		--first_touched;
	auto past_touched = first_touched;
	std::vector<ImageMapping> pieces;
	for (; past_touched != state->mappings.end() && past_touched->second.address < end; ++past_touched) {
		const auto &mapping = past_touched->second;
		const uint64_t last = mapping.address + mapping.size;
		if (mapping.address < address)
			pieces.push_back({mapping.address, address - mapping.address, 0, mapping.protection});
		const uint64_t first = std::max(mapping.address, address);
		pieces.push_back({first, std::min(last, end) - first, 0, protection});
		if (last > end)
			pieces.push_back({end, last - end, 0, mapping.protection});
	}
	memory_syscall(SYS_mprotect, address, size, static_cast<uint64_t>(protection));
	state->mappings.erase(first_touched, past_touched);
	for (const auto &piece : pieces)
		state->mappings.insert_or_assign(piece.address, piece);
}

void NativeProcess::unmap_memory(uint64_t address)
{
	state->require_stopped();
	const auto owned = std::find_if(state->allocations.begin(), state->allocations.end(), [&](const auto &allocation) {
		return allocation.first == address;
	});
	if (owned == state->allocations.end())
		throw std::runtime_error("native release requires a dynamic allocation base");
	const uint64_t end = address + owned->second;
	memory_syscall(SYS_munmap, address, owned->second);
	state->mappings.erase(state->mappings.lower_bound(address), state->mappings.lower_bound(end));
	std::erase_if(state->api_traps, [&](const auto &trap) { return trap.first >= address && trap.first < end; });
	std::erase_if(state->returning_traps, [&](const uint64_t trap) { return trap >= address && trap < end; });
	state->allocations.erase(owned);
}

bool NativeProcess::memory_available(uint64_t address, size_t size) const
{
	state->require_stopped();
	memory_range(address,size,PROT_NONE,state->limit());
	const auto end = address+size;
	const auto stack = state->initial_stack_top-1024*1024-4096;
	if (address < state->initial_stack_top+4096 && stack < end)
		return false;
	for (const auto &[start, mapping] : state->mappings)
		if (address < mapping.address+mapping.size && mapping.address < end)
			return false;
	// The host maps a few things of its own into the guest near the top of the address space (the loader, vdso, its stack); the
	// runtime does not track those, so a range up there is checked against the guest's own map.
	if (end > 0x700000000000ULL) {
		std::ifstream maps("/proc/" + std::to_string(state->child->pid) + "/maps");
		std::string line;
		while (std::getline(maps, line)) {
			uint64_t first = 0, last = 0;
			if (std::sscanf(line.c_str(), "%" SCNx64 "-%" SCNx64, &first, &last) == 2 && address < last && first < end)
				return false;
		}
	}
	return true;
}

void NativeProcess::discard_memory(uint64_t address, size_t size)
{
	state->require_stopped();
	memory_range(address,size,PROT_NONE,state->limit());
	const auto owned = std::find_if(state->allocations.begin(),state->allocations.end(),[&](const auto &allocation) {
		return address >= allocation.first && address-allocation.first < allocation.second &&
			size <= allocation.second-(address-allocation.first);
	});
	if (owned == state->allocations.end())
		throw std::runtime_error("native discard range is outside a dynamic allocation");
	memory_syscall(SYS_madvise,address,size,MADV_DONTNEED);
}

void NativeProcess::map_image(LoadedImage &image)
{
	state->require_stopped();
	const auto base = image.base();
	const auto size = image.data().size();
	memory_range(base, size, PROT_NONE, state->limit());
	const auto mappings = image.mappings();
	state->image_allocations.reserve(state->image_allocations.size() + 1);
	const auto path = "/proc/" + std::to_string(getpid()) + "/fd/" + std::to_string(image.descriptor());
	std::vector<uint8_t> name(path.begin(), path.end());
	name.push_back(0);
	uint64_t scratch = 0;
	uint64_t descriptor = uint64_t(-1);
	bool mapped = false;
	try {
		scratch = map_memory(4096, PROT_READ | PROT_WRITE);
		write_memory(scratch, name);
		// Reopen only the host-owned memfd; guest code never executes the Linux syscall.
		descriptor = memory_syscall(SYS_openat, uint64_t(AT_FDCWD), scratch, O_RDWR | O_CLOEXEC);
		const auto result = memory_syscall(SYS_mmap, base, size, PROT_NONE,
			MAP_SHARED | MAP_FIXED_NOREPLACE, descriptor);
		if (result != base) {
			state->child->stop();
			throw std::runtime_error("host returned an invalid native image address");
		}
		mapped = true;
		for (const auto &mapping : mappings)
			memory_syscall(SYS_mprotect, mapping.address, mapping.size, static_cast<uint64_t>(mapping.protection));
		memory_syscall(SYS_close, descriptor, 0);
		descriptor = uint64_t(-1);
		unmap_memory(scratch);
		scratch = 0;
		for (const auto &mapping : mappings)
			state->mappings.insert_or_assign(mapping.address, mapping);
		state->image_allocations.emplace_back(base, size);
	} catch (...) {
		try {
			if (mapped)
				memory_syscall(SYS_munmap, base, size);
			if (descriptor != uint64_t(-1))
				memory_syscall(SYS_close, descriptor, 0);
			if (scratch)
				unmap_memory(scratch);
		} catch (...) {
			state->child->stop();
		}
		throw;
	}
}

void NativeProcess::unmap_image(uint64_t address)
{
	state->require_stopped();
	const auto owned = std::find_if(state->image_allocations.begin(), state->image_allocations.end(), [&](const auto &image) {
		return image.first == address;
	});
	if (owned == state->image_allocations.end())
		throw std::runtime_error("native image release requires a dynamically mapped image base");
	const uint64_t end = address + owned->second;
	memory_syscall(SYS_munmap, address, owned->second);
	state->mappings.erase(state->mappings.lower_bound(address), state->mappings.lower_bound(end));
	std::erase_if(state->api_traps, [&](const auto &trap) { return trap.first >= address && trap.first < end; });
	std::erase_if(state->returning_traps, [&](const uint64_t trap) { return trap >= address && trap < end; });
	state->image_allocations.erase(owned);
}

std::pair<uint64_t, uint64_t> NativeProcess::stack_bounds() const
{
	state->require_stopped();
	return {state->initial_stack_top - 1024 * 1024, state->initial_stack_top};
}

bool NativeProcess::active() const
{
	state->require_stopped();
	return state->active_call;
}

void NativeProcess::abandon_call()
{
	state->require_stopped();
	if (!state->active_call || !state->awaiting_api)
		throw std::runtime_error("native abandonment requires a pending API call");
	// Termination never resumes any suspended guest caller.
	state->callbacks.clear();
	state->callback_cleanups.clear();
	state->active_call=false;
	state->awaiting_api=false;
	state->awaiting_syscall=false;
}

void NativeProcess::end_call()
{
	state->require_stopped();
	state->callbacks.clear();
	state->callback_cleanups.clear();
	state->active_call=false;
	state->awaiting_api=false;
	state->awaiting_syscall=false;
	state->translated_words.reset();
}

uint64_t NativeProcess::return_gate() const
{
	return state->mode == NativeMode::x86 ? state->return_gate : state->child->gate;
}

uint64_t NativeProcess::result_register() const
{
	state->require_stopped();
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, state->child->pid, &registers);
	return registers.rax;
}

size_t NativeProcess::callback_depth() const
{
	return state->callbacks.size();
}

void NativeProcess::trace_instructions(size_t count, std::function<void(uint64_t)> sink)
{
	state->require_stopped();
	state->steps_left = count;
	state->step_sink = std::move(sink);
}

void NativeProcess::watch_write(uint64_t address)
{
	state->require_stopped();
	const pid_t pid = state->child->pid;
	const auto poke = [&](size_t index, uint64_t value) {
		const long offset = long(offsetof(struct user, u_debugreg)) + long(index * sizeof(unsigned long));
		if (ptrace(PTRACE_POKEUSER, pid, reinterpret_cast<void *>(offset), reinterpret_cast<void *>(value)) == -1)
			throw std::runtime_error("cannot program the debug registers");
	};
	poke(7, 0);
	if (!address)
		return;
	poke(0, address);
	// Local enable of slot 0, write trigger (01) and eight-byte length (10 on x86-64, encoded as 0b10).
	poke(7, 1 | (1ULL << 16) | (2ULL << 18));
}

NativeThreadState NativeProcess::save_thread() const
{
	state->require_stopped();
	return {context(), state->callbacks, state->callback_cleanups, state->active_call, state->awaiting_api, state->awaiting_syscall,
		state->debug_print_fault, state->pending_cleanup, state->stack_top, state->translated_words, state->translated_depth,
		state->translated_floats, state->translated_result};
}

void NativeProcess::load_thread(const NativeThreadState &thread)
{
	state->require_stopped();
	set_context(thread.context);
	state->callbacks = thread.callbacks;
	state->callback_cleanups = thread.callback_cleanups;
	state->active_call = thread.active_call;
	state->awaiting_api = thread.awaiting_api;
	state->awaiting_syscall = thread.awaiting_syscall;
	state->debug_print_fault = thread.debug_print_fault;
	state->pending_cleanup = thread.pending_cleanup;
	state->stack_top = thread.stack_top;
	state->translated_words = thread.translated_words;
	state->translated_depth = thread.translated_depth;
	state->translated_floats = thread.translated_floats;
	state->translated_result = thread.translated_result;
	state->slice_started = std::chrono::steady_clock::now();
	if (state->mode == NativeMode::x86) {
		state->fs_selector = uint32_t(thread.context.registers.fs);
		state->fs_base = thread.context.registers.fs_base;
	}
}

NativeThreadState NativeProcess::new_thread(uint64_t stack_top, uint64_t teb)
{
	state->require_stopped();
	NativeThreadState thread{};
	thread.context = context();
	if (state->mode == NativeMode::x86) {
		// Every thread owns an LDT entry, so a switch only reloads registers.
		const uint32_t entry = state->ldt_entries++;
		install_segment(entry, teb);
		thread.context.registers.fs = entry * 8 + 7;
		thread.context.registers.fs_base = teb;
	} else {
		thread.context.registers.gs_base = teb;
	}
	thread.stack_top = stack_top;
	return thread;
}

void NativeProcess::enter_fault_dispatch()
{
	state->require_stopped();
	if (!state->active_call || state->awaiting_api || state->awaiting_syscall || state->mode != NativeMode::x64)
		throw std::runtime_error("native fault dispatch requires a stopped x64 call");
	state->awaiting_api = true;
	state->pending_cleanup = 0;
}

void NativeProcess::redirect(const NativeContext &target, size_t depth)
{
	state->require_stopped();
	if (!state->active_call || !state->awaiting_api || depth > state->callbacks.size())
		throw std::runtime_error("native redirection requires a pending API call");
	set_context(target);
	state->callbacks.resize(depth);
	state->callback_cleanups.resize(depth);
	state->awaiting_api = false;
	state->awaiting_syscall = false;
}

NativeMode NativeProcess::mode() const
{
	return state->mode;
}

void NativeProcess::set_teb(uint64_t base)
{
	state->require_stopped();
	install_segment(0, base);
	// LDT index 0, table indicator 1, requested privilege level 3.
	state->fs_selector = 7;
	state->fs_base = base;
}

void NativeProcess::install_segment(uint32_t entry, uint64_t base)
{
	if (state->mode != NativeMode::x86 || base > 0xfffff000ULL || base % 4096)
		throw std::runtime_error("native TEB descriptor requires an x86 process and a page-aligned 32-bit address");
	// struct user_desc: entry, base, limit, flags (32-bit segment, data, byte granularity, usable).
	std::vector<uint8_t> descriptor(16);
	const uint32_t fields[] = {entry, uint32_t(base), 0xfff, 0x41};
	for (size_t index = 0; index < 4; ++index)
		for (size_t byte = 0; byte < 4; ++byte)
			descriptor[index * 4 + byte] = uint8_t(fields[index] >> (byte * 8));
	const auto scratch = map_memory(4096, PROT_READ | PROT_WRITE);
	try {
		write_memory(scratch, descriptor);
		const auto result = memory_syscall(SYS_modify_ldt, 1, scratch, descriptor.size());
		if (result != 0)
			throw std::runtime_error("host rejected the native TEB descriptor");
	} catch (...) {
		if (state->child->pid != -1)
			unmap_memory(scratch);
		throw;
	}
	unmap_memory(scratch);
}

void NativeProcess::add_api_trap(uint64_t address, uint32_t callee_cleanup)
{
	state->require_stopped();
	if (!state->covers(address, 1, PROT_EXEC) || read_memory(address, 1)[0] != 0xcc)
		throw std::runtime_error("native API trap must be an executable INT3");
	if (state->mode == NativeMode::x86 && (address >= state->limit() || callee_cleanup % 4))
		throw std::runtime_error("native x86 API trap requires a 32-bit address and dword-aligned cleanup");
	state->api_traps[address] = callee_cleanup;
	if (state->mode != NativeMode::x86 && state->covers(address + 1, 1, PROT_EXEC) && read_memory(address + 1, 1)[0] == 0xc3)
		state->returning_traps.insert(address);
	else
		state->returning_traps.erase(address);
}

NativeResult NativeProcess::call(uint64_t address, std::span<const uint64_t> arguments,
	std::chrono::milliseconds timeout)
{
	state->require_stopped();
	if (state->active_call)
		throw std::runtime_error("native call is already active");
	return begin_call(address, arguments, state->stack_top, timeout);
}

NativeResult NativeProcess::callback(uint64_t address, std::span<const uint64_t> arguments,
	std::chrono::milliseconds timeout)
{
	state->require_stopped();
	if (!state->active_call || !state->awaiting_api) {
		if (std::getenv("RAVEN_BACKTRACE")) {
			void *frames[40];
			const int count = backtrace(frames, 40);
			backtrace_symbols_fd(frames, count, 2);
		}
		throw std::runtime_error(std::string("native callback requires a pending API call (last API ") + api_in_progress + ")");
	}
	if (state->callbacks.size() >= 64)
		throw std::runtime_error("native callback exceeds initial nesting limit");
	const auto saved = context();
	state->callbacks.push_back(saved);
	// A nested API trap overwrites the pending stdcall cleanup of the call that was interrupted.
	state->callback_cleanups.push_back(state->pending_cleanup);
	try {
		return begin_call(address, arguments, saved.registers.rsp & ~uint64_t(15), timeout);
	} catch (...) {
		if (state->stopped && state->child->pid != -1) {
			try {
				set_context(saved);
			} catch (...) {
				state->child->stop();
				throw;
			}
			state->callbacks.pop_back();
			state->pending_cleanup = state->callback_cleanups.back();
			state->callback_cleanups.pop_back();
			state->awaiting_api = true;
		} else {
			state->child->stop();
		}
		throw;
	}
}

NativeResult NativeProcess::begin_call(uint64_t address, std::span<const uint64_t> arguments,
	uint64_t stack_ceiling, std::chrono::milliseconds timeout)
{
	if (arguments.size() > 128)
		throw std::runtime_error("native call exceeds initial argument limit");
	if (!state->covers(address, 1, PROT_EXEC))
		throw std::runtime_error("native entry is outside executable image memory");
	state->child->set_timeout(timeout);
	if (state->mode == NativeMode::x86)
		return begin_x86_call(address, arguments, stack_ceiling, timeout);
	const size_t extra = arguments.size() > 4 ? (arguments.size() - 4) * 8 : 0;
	const size_t frame_size = ((32 + extra + 15) & ~size_t(15)) + 8;
	if (stack_ceiling < frame_size)
		throw std::runtime_error("native call stack address underflows");
	const uint64_t rsp = stack_ceiling - frame_size;
	std::vector<uint8_t> frame(frame_size);
	const auto put = [&](size_t offset, uint64_t value) {
		for (size_t byte = 0; byte < 8; ++byte)
			frame[offset + byte] = static_cast<uint8_t>(value >> (byte * 8));
	};
	put(0, state->child->gate);
	for (size_t index = 4; index < arguments.size(); ++index)
		put(40 + (index - 4) * 8, arguments[index]);
	write_memory(rsp, frame);
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, state->child->pid, &registers);
	registers.rax = 0;
	registers.rcx = arguments.size() > 0 ? arguments[0] : 0;
	registers.rdx = arguments.size() > 1 ? arguments[1] : 0;
	registers.r8 = arguments.size() > 2 ? arguments[2] : 0;
	registers.r9 = arguments.size() > 3 ? arguments[3] : 0;
	registers.orig_rax = uint64_t(-1);
	registers.eflags = 0x202;
	registers.rip = address;
	registers.rsp = rsp;
	trace(PTRACE_SETREGS, state->child->pid, &registers);
	state->active_call = true;
	state->awaiting_api = false;
	state->awaiting_syscall = false;
	state->debug_print_fault = false;
	return resume(timeout);
}

NativeResult NativeProcess::begin_x86_call(uint64_t address, std::span<const uint64_t> arguments,
	uint64_t stack_ceiling, std::chrono::milliseconds timeout)
{
	if (std::any_of(arguments.begin(), arguments.end(), [](uint64_t value) { return value > UINT32_MAX; }))
		throw std::runtime_error("native x86 call argument exceeds 32 bits");
	const uint64_t size = arguments.size() * 4;
	if (stack_ceiling > state->limit() || stack_ceiling < size + 16)
		throw std::runtime_error("native call stack address is invalid");
	// Win32 entry points see ESP+4 on a 16-byte boundary so compiler-aligned locals stay aligned.
	const uint64_t first_argument = (stack_ceiling - size) & ~uint64_t(15);
	const uint64_t esp = first_argument - 4;
	std::vector<uint8_t> frame(4 + size);
	const auto put = [&](size_t offset, uint64_t value) {
		for (size_t byte = 0; byte < 4; ++byte)
			frame[offset + byte] = static_cast<uint8_t>(value >> (byte * 8));
	};
	put(0, state->return_gate);
	for (size_t index = 0; index < arguments.size(); ++index)
		put(4 + index * 4, arguments[index]);
	write_memory(esp, frame);
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, state->child->pid, &registers);
	registers.rax = registers.rcx = registers.rdx = 0;
	registers.orig_rax = uint64_t(-1);
	registers.eflags = 0x202;
	registers.rip = address;
	registers.rsp = esp;
	registers.cs = 0x23;
	registers.ss = registers.ds = registers.es = 0x2b;
	// The host reloads FS bases from thread state on every switch-in, so the selector and the descriptor base must agree.
	registers.fs = state->fs_selector;
	registers.fs_base = state->fs_base;
	registers.gs = 0;
	registers.gs_base = 0;
	trace(PTRACE_SETREGS, state->child->pid, &registers);
	state->active_call = true;
	state->awaiting_api = false;
	state->awaiting_syscall = false;
	state->debug_print_fault = false;
	return resume(timeout);
}

NativeResult NativeProcess::resume(std::chrono::milliseconds timeout)
{
	state->require_stopped();
	if (!state->active_call || state->awaiting_api) {
		if (std::getenv("RAVEN_BACKTRACE")) {
			void *frames[40];
			const int count = backtrace(frames, 40);
			backtrace_symbols_fd(frames, count, 2);
		}
		throw std::runtime_error(std::string("native process has no resumable call or awaits an API response (last API ") + api_in_progress + ")");
	}
	auto &child = *state->child;
	child.set_timeout(timeout);
	int status;
	user_regs_struct registers{};
	int signal;
	std::optional<siginfo_t> event_info;
	for (;;) {
		// SYSEMU blocks host syscall dispatch; invalid syscall gates can fault first. Diagnostics may single-step instead.
		const bool slicing = state->slice.count() > 0 && state->slice_yield && state->slice_wanted && state->slice_wanted();
		// A guest that keeps calling the runtime never has a quiet slice, so the time it has had the processor is checked at every resumption too.
		// A thread inside a served stub keeps the processor until it leaves it: the block it uses is shared by every thread.
		std::chrono::steady_clock::duration period = state->slice;
		if (slicing && std::chrono::steady_clock::now() - state->slice_started >= state->slice) {
			if (inside_served_stub()) {
				period = std::chrono::microseconds(100);
			} else {
				state->slice_yield();
				state->slice_started = std::chrono::steady_clock::now();
			}
		}
		// Sampling interrupts the guest on its own, shorter period; a thread change still waits for the whole slice.
		const bool sampling = state->sample_period.count() > 0 && state->sampler;
		if (slicing || sampling)
			child.set_slice(slicing && sampling ? std::min<std::chrono::steady_clock::duration>(period, state->sample_period) : slicing ? period :
				state->sample_period);
		else
			child.clear_slice();
		event_info.reset();
		if (state->resume_hook)
			state->resume_hook();
		trace(state->steps_left ? PTRACE_SINGLESTEP : state->seccomp ? PTRACE_CONT : PTRACE_SYSEMU, child.pid);
		state->stopped = false;
		status = child.wait(state->poll_served ? &state->poll_served : nullptr);
		// The slice belongs to this resume only; a later wait for a memory operation of the runtime must not see it expire.
		child.clear_slice();
		if (status == -2) {
			// The guest ran a whole slice without a stop of its own: interrupt it where it is and let another thread have the processor.
			child.clear_slice();
			kill(child.pid, SIGSTOP);
			int interrupted = 0;
			while (waitpid(child.pid, &interrupted, 0) == -1 && errno == EINTR) {}
			if (!WIFSTOPPED(interrupted))
				throw std::runtime_error("native guest exited outside the runtime boundary");
			if (WSTOPSIG(interrupted) == SIGSTOP) {
				state->stopped = true;
				if (sampling) {
					user_regs_struct where{};
					trace(PTRACE_GETREGS, child.pid, &where);
					state->sampler(where.rip);
				}
				// Whether another thread wants the processor is asked again: it may have become ready through a served call meanwhile. When
				// none does, this thread starts a new slice, so the next served call does not interrupt it at once.
				const bool wanted = state->slice.count() > 0 && state->slice_yield && state->slice_wanted && state->slice_wanted();
				if (wanted && std::chrono::steady_clock::now() - state->slice_started >= state->slice && !inside_served_stub()) {
					state->slice_yield();
					state->slice_started = std::chrono::steady_clock::now();
				} else if (!wanted) {
					state->slice_started = std::chrono::steady_clock::now();
				}
				continue;
			}
			// A stop of the guest's own came first and the interrupt is still pending. Keep what describes that stop, then let the
			// pending signal be delivered: it arrives before the guest runs another instruction, and a resume without a signal drops it.
			siginfo_t kept{};
			trace(PTRACE_GETSIGINFO, child.pid, &kept);
			event_info = kept;
			status = interrupted;
			forget_registers();
			ptrace(state->seccomp ? PTRACE_CONT : PTRACE_SYSEMU, child.pid, nullptr, nullptr);
			int drained = 0;
			while (waitpid(child.pid, &drained, 0) == -1 && errno == EINTR) {}
			if (!WIFSTOPPED(drained) || WSTOPSIG(drained) != SIGSTOP)
				throw std::runtime_error("native guest did not stop for the pending interrupt");
		}
		if (status == -1) {
			if (std::getenv("RAVEN_TRACE_API")) {
				user_regs_struct where{};
				if (ptrace(PTRACE_INTERRUPT, child.pid, 0, 0) == 0 || true) {
					kill(child.pid, SIGSTOP);
					int ignored = 0;
					waitpid(child.pid, &ignored, 0);
					if (ptrace(PTRACE_GETREGS, child.pid, 0, &where) == 0)
						std::cerr << "raven: guest timeout at rip=0x" << std::hex << where.rip << " rsp=0x" << where.rsp << std::dec << '\n';
				}
			}
			child.stop();
			return {NativeStop::timeout, 0, 0, 0};
		}
		if (!WIFSTOPPED(status))
			throw std::runtime_error("native guest exited outside the runtime boundary");
		state->stopped = true;
		trace(PTRACE_GETREGS, child.pid, &registers);
		signal = WSTOPSIG(status);
		if (state->seccomp && signal == SIGTRAP && (status >> 16) == PTRACE_EVENT_SECCOMP)
			signal = SIGTRAP | 0x80;
		// A served stub that waited too long stops on its own breakpoint: its call is answered and it goes on where it stopped.
		if (signal == SIGTRAP && served_wait_trap(registers.rip - 1)) {
			serve_pending();
			continue;
		}
		if (state->steps_left && signal == SIGTRAP) {
			siginfo_t step{};
			trace(PTRACE_GETSIGINFO, child.pid, &step);
			if (step.si_code == TRAP_TRACE || step.si_code == 0) {
				if (state->step_sink)
					state->step_sink(registers.rip);
				--state->steps_left;
				continue;
			}
		}
		break;
	}
	if (signal == (SIGTRAP | 0x80)) {
		state->awaiting_syscall = true;
		return {NativeStop::syscall, registers.orig_rax, registers.rip, signal};
	}
	state->awaiting_syscall = false;
	siginfo_t info{};
	const bool x86 = state->mode == NativeMode::x86;
	// A trap right after the gate or an API breakpoint is that breakpoint: the stop reason is known without asking for it.
	if (event_info)
		info = *event_info;
	else if (signal == SIGTRAP && (registers.rip == (x86 ? state->return_gate : child.gate) + 1 || state->api_traps.contains(registers.rip - 1)))
		info.si_code = SI_KERNEL;
	else
		trace(PTRACE_GETSIGINFO, child.pid, &info);
	state->debug_print_fault=signal==SIGSEGV && info.si_code==SI_KERNEL && registers.rax==1;
	if (signal == SIGTRAP && info.si_code == TRAP_HWBKPT) {
		// Reading the stop reason is enough; DR6 must be cleared or the next trap reports a stale cause.
		ptrace(PTRACE_POKEUSER, child.pid, reinterpret_cast<void *>(offsetof(struct user, u_debugreg) + 6 * sizeof(unsigned long)), nullptr);
	}
	const bool breakpoint = signal == SIGTRAP && (info.si_code == TRAP_BRKPT || info.si_code == SI_KERNEL);
	if (breakpoint && registers.rip == (x86 ? state->return_gate : child.gate) + 1) {
		if (state->callbacks.empty()) {
			state->active_call = false;
		} else {
			try {
				set_context(state->callbacks.back());
			} catch (...) {
				child.stop();
				throw;
			}
			state->callbacks.pop_back();
			state->pending_cleanup = state->callback_cleanups.back();
			state->callback_cleanups.pop_back();
			state->awaiting_api = true;
		}
		return {NativeStop::returned, x86 ? registers.rax & 0xffffffff : registers.rax, registers.rip, signal};
	}
	if (breakpoint && state->api_traps.contains(registers.rip - 1)) {
		state->awaiting_api = true;
		state->pending_cleanup = state->api_traps.at(registers.rip - 1);
		return {NativeStop::api, registers.rip - 1, registers.rip, signal};
	}
	const uint64_t fault_address = signal == SIGSEGV || signal == SIGBUS || signal == SIGILL || signal == SIGFPE ?
		reinterpret_cast<uint64_t>(info.si_addr) : 0;
	return {NativeStop::fault, registers.rax, registers.rip, signal, fault_address, info.si_code};
}

void NativeProcess::set_api_argument(size_t index, uint32_t value)
{
	state->require_stopped();
	if (!state->awaiting_api || state->mode != NativeMode::x86 || index > 127)
		throw std::runtime_error("native argument rewrite requires a pending x86 API call");
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, state->child->pid, &registers);
	const uint8_t bytes[4] = {uint8_t(value), uint8_t(value >> 8), uint8_t(value >> 16), uint8_t(value >> 24)};
	write_memory(registers.rsp + 4 + index * 4, bytes);
}

void NativeProcess::set_time_slicing(std::chrono::milliseconds slice, std::function<bool()> wanted, std::function<void()> yield)
{
	state->slice = slice;
	state->slice_wanted = std::move(wanted);
	state->slice_yield = std::move(yield);
}

void NativeProcess::set_guest_sampler(std::chrono::milliseconds period, std::function<void(uint64_t)> sampler)
{
	state->sample_period = period;
	state->sampler = std::move(sampler);
}

void NativeProcess::set_served_calls(uint64_t *block, std::vector<uint64_t> stubs, size_t stub_size, size_t wait_offset,
	std::function<void(uint64_t)> handler)
{
	std::sort(stubs.begin(), stubs.end());
	state->served_wait_offset = wait_offset;
	state->served_block = block;
	state->served_stubs = std::move(stubs);
	state->served_stub_size = stub_size;
	state->served_handler = std::move(handler);
	state->poll_served = [this] {
		if (!serve_pending())
			return false;
		// A served call can make another thread ready (a wake) without the guest stopping, so the guest gets a slice to be measured
		// against if it has none.
		if (state->slice.count() > 0 && state->slice_yield)
			state->child->ensure_slice(state->slice_started + state->slice);
		return true;
	};
}

bool NativeProcess::served_wait_trap(uint64_t address) const
{
	const auto after = std::upper_bound(state->served_stubs.begin(), state->served_stubs.end(), address);
	return after != state->served_stubs.begin() && address - *(after - 1) == state->served_wait_offset;
}

bool NativeProcess::inside_served_stub() const
{
	if (state->served_stubs.empty())
		return false;
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, state->child->pid, &registers);
	const auto after = std::upper_bound(state->served_stubs.begin(), state->served_stubs.end(), registers.rip);
	return after != state->served_stubs.begin() && registers.rip - *(after - 1) < state->served_stub_size;
}

bool NativeProcess::serve_pending()
{
	uint64_t *block = state->served_block;
	if (!block)
		return false;
	const uint64_t stub = __atomic_load_n(&block[0], __ATOMIC_ACQUIRE);
	if (!stub)
		return false;
	// Block layout: the stub's address, RCX, RDX, R8, R9, RSP, the low halves of XMM0 to XMM3, then the result.
	std::vector<uint64_t> words{block[1], block[2], block[3], block[4]};
	const uint64_t stack = block[5] + 40;
	const std::array<uint64_t, 4> floats{block[6], block[7], block[8], block[9]};
	auto translated_words = std::move(state->translated_words);
	const auto translated_depth = state->translated_depth;
	const auto translated_floats = state->translated_floats;
	const auto translated_result = state->translated_result;
	state->translated_words.reset();
	const bool was_serving = state->serving;
	const uint64_t was_stack = state->served_stack;
	state->serving = true;
	state->served_stack = stack;
	const auto restore = [&] {
		state->translated_words = std::move(translated_words);
		state->translated_depth = translated_depth;
		state->translated_floats = translated_floats;
		state->translated_result = translated_result;
		state->serving = was_serving;
		state->served_stack = was_stack;
	};
	try {
		begin_translated_call(std::move(words), floats);
		state->served_handler(stub);
		block[10] = end_translated_call();
	} catch (...) {
		state->translated_words.reset();
		restore();
		throw;
	}
	restore();
	if (state->resume_hook)
		state->resume_hook();
	__atomic_store_n(&block[0], 0, __ATOMIC_RELEASE);
	return true;
}

void NativeProcess::set_resume_hook(std::function<void()> hook)
{
	state->resume_hook = std::move(hook);
}

void NativeProcess::begin_translated_call(std::vector<uint64_t> words, std::array<uint64_t, 4> floats)
{
	if (state->translated_words)
		throw std::runtime_error("a translated native call is already running");
	state->translated_words = std::move(words);
	state->translated_depth = state->callbacks.size();
	state->translated_floats = floats;
	state->translated_result = 0;
}

uint64_t NativeProcess::end_translated_call()
{
	state->translated_words.reset();
	return state->translated_result;
}

std::vector<uint64_t> NativeProcess::api_arguments(size_t count) const
{
	state->require_stopped();
	if (state->translated_words && state->callbacks.size() == state->translated_depth) {
		auto words = *state->translated_words;
		if (state->serving && count > words.size() && count <= 128) {
			const auto stack = read_memory(state->served_stack, (count - words.size()) * 8);
			for (size_t offset = 0; offset < stack.size(); offset += 8) {
				uint64_t value = 0;
				std::memcpy(&value, stack.data() + offset, 8);
				words.push_back(value);
			}
		}
		words.resize(count);
		return words;
	}
	if (!state->awaiting_api || count > 128)
		throw std::runtime_error("native process is not at an API or exceeds argument limit");
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, state->child->pid, &registers);
	if (state->mode == NativeMode::x86) {
		std::vector<uint64_t> values(count);
		if (!count)
			return values;
		const auto stack = read_memory(registers.rsp + 4, count * 4);
		for (size_t index = 0; index < count; ++index)
			for (size_t byte = 0; byte < 4; ++byte)
				values[index] |= uint64_t(stack[index * 4 + byte]) << (byte * 8);
		return values;
	}
	const uint64_t first[] = {registers.rcx, registers.rdx, registers.r8, registers.r9};
	std::vector<uint64_t> arguments(count);
	for (size_t index = 0; index < std::min(count, size_t(4)); ++index)
		arguments[index] = first[index];
	if (count > 4) {
		if (registers.rsp > UINT64_MAX - 40)
			throw std::runtime_error("native API stack address overflows");
		const auto stack = read_memory(registers.rsp + 40, (count - 4) * 8);
		for (size_t index = 4; index < count; ++index) {
			for (size_t byte = 0; byte < 8; ++byte)
				arguments[index] |= uint64_t(stack[(index - 4) * 8 + byte]) << (byte * 8);
		}
	}
	return arguments;
}

std::array<uint64_t, 4> NativeProcess::api_float_arguments() const
{
	state->require_stopped();
	if (state->translated_words && state->callbacks.size() == state->translated_depth)
		return state->translated_floats;
	if (!state->awaiting_api || state->mode != NativeMode::x64)
		throw std::runtime_error("native process is not at an x64 API call");
	user_fpregs_struct registers{};
	trace(PTRACE_GETFPREGS, state->child->pid, &registers);
	std::array<uint64_t, 4> result{};
	for (size_t index = 0; index < 4; ++index)
		std::memcpy(&result[index], reinterpret_cast<const uint8_t *>(registers.xmm_space) + index * 16, 8);
	return result;
}

void NativeProcess::enter_nt_service(uint64_t instruction, uint32_t number)
{
	state->require_stopped();
	if (state->mode != NativeMode::x64)
		throw std::runtime_error("native NT services are x64 only");
	if (!state->active_call || state->awaiting_api || !state->awaiting_syscall)
		throw std::runtime_error("native process is not at a pending syscall service");
	auto saved=context();
	if (saved.registers.rip!=instruction || saved.registers.orig_rax!=number || instruction<2 ||
		read_memory(instruction-2,2)!=std::vector<uint8_t>{0x0f,0x05} || !state->covers(instruction-2,3,PROT_EXEC) ||
		read_memory(instruction,1)!=std::vector<uint8_t>{0xc3})
		throw std::runtime_error("native NT service boundary does not match the captured syscall");
	// x64 NT service stubs preserve argument one in R10 before SYSCALL replaces RCX.
	saved.registers.rcx=saved.registers.r10;
	saved.registers.orig_rax=uint64_t(-1);
	set_context(saved);
	state->awaiting_syscall=false;
	state->awaiting_api=true;
}

void NativeProcess::complete_debug_print(uint64_t instruction)
{
	state->require_stopped();
	if (state->mode != NativeMode::x64)
		throw std::runtime_error("native debug print services are x64 only");
	const auto saved=context();
	if (!state->active_call || state->awaiting_api || state->awaiting_syscall || !state->debug_print_fault ||
		saved.registers.rip!=instruction || saved.registers.rax!=1 || !state->covers(instruction,4,PROT_EXEC) ||
		read_memory(instruction,4)!=std::vector<uint8_t>{0xcd,0x2d,0xcc,0xc3})
		throw std::runtime_error("native debug print does not match a captured INT 2D service");
	state->debug_print_fault=false;
	state->awaiting_api=true;
	return_api(0);
}

void NativeProcess::return_api(uint64_t value)
{
	state->require_stopped();
	if (state->translated_words && state->callbacks.size() == state->translated_depth) {
		state->translated_result = value;
		return;
	}
	if (!state->awaiting_api)
		throw std::runtime_error("native process is not awaiting an API result");
	user_regs_struct registers{};
	trace(PTRACE_GETREGS, state->child->pid, &registers);
	if (state->mode == NativeMode::x86) {
		if (std::getenv("RAVEN_TRACE_X86"))
			std::fprintf(stderr, "  -> %llx\n", static_cast<unsigned long long>(value & 0xffffffffULL));
		const auto stack = read_memory(registers.rsp, 4);
		registers.rip = 0;
		for (size_t byte = 0; byte < 4; ++byte)
			registers.rip |= uint64_t(stack[byte]) << (byte * 8);
		registers.rsp += 4 + state->pending_cleanup;
		registers.rax = value & 0xffffffff;
		registers.rdx = value >> 32;
		registers.orig_rax = uint64_t(-1);
		trace(PTRACE_SETREGS, state->child->pid, &registers);
		state->awaiting_api = false;
		return;
	}
	// Stopped right after a breakpoint that a RET follows: the guest returns by itself.
	if (state->returning_traps.contains(registers.rip - 1)) {
		registers.rax = value;
		registers.orig_rax = uint64_t(-1);
		trace(PTRACE_SETREGS, state->child->pid, &registers);
		state->awaiting_api = false;
		return;
	}
	if (registers.rsp > UINT64_MAX - 8)
		throw std::runtime_error("native API return stack address overflows");
	const auto stack = read_memory(registers.rsp, 8);
	registers.rip = 0;
	for (size_t byte = 0; byte < 8; ++byte)
		registers.rip |= uint64_t(stack[byte]) << (byte * 8);
	registers.rsp += 8;
	registers.rax = value;
	registers.orig_rax = uint64_t(-1);
	trace(PTRACE_SETREGS, state->child->pid, &registers);
	state->awaiting_api = false;
}

static NativeResult execute(const PEImage &image, LoadedImage &loaded, std::span<LoadedImage *const> images,
	const std::string &bootstrap, std::chrono::milliseconds timeout)
{
	NativeProcess process(images, bootstrap, timeout);
	return process.call(loaded.base() + image.entry, {}, timeout);
}

NativeResult run_native_entry(const PEImage &image, LoadedImage &loaded,
	const std::string &bootstrap, std::chrono::milliseconds timeout)
{
	if (!image.is_64)
		throw std::runtime_error("native PE32 execution is not implemented");
	if ((image.characteristics & 0x2000) != 0 || !image.imports().empty() ||
		image.directories[9].size != 0 || image.directories[13].size != 0 || image.directories[14].size != 0)
		throw std::runtime_error("native entry requires an executable without imports, TLS, delayed imports or CLR initialization");
	LoadedImage *images[] = {&loaded};
	return execute(image, loaded, images, bootstrap, timeout);
}

NativeResult run_native_modules(ModuleSet &modules, PEModule &entry,
	const std::string &bootstrap, std::chrono::milliseconds timeout)
{
	if ((entry.image.characteristics & 0x2000) != 0 ||
		!std::any_of(modules.all().begin(), modules.all().end(), [&](const auto &item) { return item.second.get() == &entry; }))
		throw std::runtime_error("native module entry must be an executable in the supplied graph");
	std::vector<LoadedImage *> images;
	for (const auto &[name, module] : modules.all()) {
		if (!module->image.is_64)
			throw std::runtime_error("native PE32 execution is not implemented");
		if (module->image.directories[9].size || module->image.directories[13].size || module->image.directories[14].size ||
			((module->image.characteristics & 0x2000) != 0 && module->image.entry))
			throw std::runtime_error("native module requires unsupported DLL, TLS, delayed import or CLR initialization: " + name);
		images.push_back(&module->loaded);
	}
	modules.bind_imports();
	return execute(entry.image, entry.loaded, images, bootstrap, timeout);
}

}

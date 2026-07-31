#include "native_cpu.h"
#include <cstddef>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <elf.h>
#include <fcntl.h>
#include <map>
#include <signal.h>
#include <stdexcept>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace raven {

static void trace(enum __ptrace_request operation, pid_t child, void *data = nullptr)
{
	if (ptrace(operation, child, nullptr, data) == -1)
		throw std::runtime_error("native ptrace: " + std::string(std::strerror(errno)));
}

class NativeChild {
public:
	NativeChild(std::span<const int> image_fds, const std::string &bootstrap, std::chrono::milliseconds timeout);
	~NativeChild();
	NativeChild(const NativeChild &) = delete;
	NativeChild &operator=(const NativeChild &) = delete;
	pid_t pid = -1;
	uint64_t gate = 0;
	int wait();
	uint64_t syscall(uint64_t number, uint64_t a1 = 0, uint64_t a2 = 0, uint64_t a3 = 0,
		uint64_t a4 = 0, uint64_t a5 = 0, uint64_t a6 = 0);
	void stop();
	void set_timeout(std::chrono::milliseconds timeout);

private:
	std::chrono::steady_clock::time_point deadline;
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
	pid = -1;
}

int NativeChild::wait()
{
	// Guest code usually reaches its next trap within microseconds, so poll hot first and back off only for long-running calls.
	unsigned polls = 0;
	std::chrono::microseconds pause{20};
	for (;;) {
		int status = 0;
		const pid_t result = waitpid(pid, &status, WNOHANG);
		if (result == pid) {
			if (WIFEXITED(status) || WIFSIGNALED(status))
				pid = -1;
			return status;
		}
		if (result == -1 && errno != EINTR)
			throw std::runtime_error("cannot wait for native guest");
		if (++polls < 4000)
			continue;
		if (std::chrono::steady_clock::now() >= deadline)
			return -1;
		std::this_thread::sleep_for(pause);
		pause = std::min(pause * 2, std::chrono::microseconds(1000));
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
	// PTRACE_CONT executes only this owned gate, never guest code.
	trace(PTRACE_CONT, pid);
	const int status = wait();
	if (status == -1 || !WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP)
		throw std::runtime_error("native syscall did not reach its trap");
	trace(PTRACE_GETREGS, pid, &registers);
	if (registers.rip != gate + 4)
		throw std::runtime_error("native syscall stopped outside its gate");
	if (registers.rax >= uint64_t(-4095))
		throw std::runtime_error("native syscall: " + std::string(std::strerror(static_cast<int>(-registers.rax))));
	return registers.rax;
}

struct NativeProcess::State {
	std::unique_ptr<NativeChild> child;
	std::vector<ImageMapping> mappings;
	std::vector<std::pair<uint64_t, uint64_t>> allocations;
	std::vector<std::pair<uint64_t, uint64_t>> image_allocations;
	std::map<uint64_t, uint32_t> api_traps;
	NativeMode mode = NativeMode::x64;
	uint64_t return_gate = 0;
	uint32_t fs_selector = 0;
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
	bool debug_print_fault = false;
	size_t steps_left = 0;
	std::function<void(uint64_t)> step_sink;
	void require_stopped() const;
	bool covers(uint64_t address, size_t size, int protection) const;
	uint64_t limit() const { return mode == NativeMode::x86 ? 0x100000000ULL : 0x800000000000ULL; }
};

void NativeProcess::State::require_stopped() const
{
	if (!stopped || !child || child->pid == -1)
		throw std::runtime_error("native process is not stopped and alive");
}

bool NativeProcess::State::covers(uint64_t address, size_t size, int protection) const
{
	if (size > UINT64_MAX - address)
		return false;
	const uint64_t end = address + size;
	while (address < end) {
		const auto found = std::find_if(mappings.begin(), mappings.end(), [&](const auto &mapping) {
			return address >= mapping.address && address - mapping.address < mapping.size &&
				(mapping.protection & protection) == protection;
		});
		if (found == mappings.end())
			return false;
		address = std::min(end, found->address + found->size);
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
			state->mappings.push_back(mapping);
		}
	}
	const uint64_t stack_size = 1024 * 1024;
	const uint64_t low_flag = mode == NativeMode::x86 ? MAP_32BIT : 0;
	const auto stack = child.syscall(SYS_mmap, 0, stack_size + 8192, PROT_NONE,
		MAP_PRIVATE | MAP_ANONYMOUS | low_flag, uint64_t(-1));
	if (stack + stack_size + 8192 > state->limit())
		throw std::runtime_error("host placed the native stack outside the guest address space");
	child.syscall(SYS_mprotect, stack + 4096, stack_size, PROT_READ | PROT_WRITE);
	state->mappings.push_back({stack + 4096, stack_size, 0, PROT_READ | PROT_WRITE});
	state->stack_top = stack + 4096 + stack_size;
	state->initial_stack_top = state->stack_top;
	if (mode == NativeMode::x86) {
		// 32-bit return addresses cannot name the 64-bit bootstrap gate, so calls return through an INT3 page below 4 GiB.
		const auto page = child.syscall(SYS_mmap, 0, 4096, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, uint64_t(-1));
		if (page + 4096 > state->limit())
			throw std::runtime_error("host placed the native return gate outside the guest address space");
		state->mappings.push_back({page, 4096, 0, PROT_READ | PROT_WRITE});
		write_memory(page, std::vector<uint8_t>{0xcc});
		child.syscall(SYS_mprotect, page, 4096, PROT_READ | PROT_EXEC);
		state->mappings.back().protection = PROT_READ | PROT_EXEC;
		state->return_gate = page;
	}
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

NativeContext NativeProcess::context() const
{
	state->require_stopped();
	NativeContext result{};
	trace(PTRACE_GETREGS, state->child->pid, &result.registers);
	result.xstate.resize(65536);
	iovec buffer{result.xstate.data(), result.xstate.size()};
	if (ptrace(PTRACE_GETREGSET, state->child->pid, reinterpret_cast<void *>(NT_X86_XSTATE), &buffer) == -1)
		throw std::runtime_error("host cannot expose native XSTATE");
	if (buffer.iov_len < 512 || buffer.iov_len >= result.xstate.size())
		throw std::runtime_error("invalid native XSTATE size");
	result.xstate.resize(buffer.iov_len);
	return result;
}

void NativeProcess::set_context(const NativeContext &context)
{
	state->require_stopped();
	const auto previous = this->context();
	if (context.xstate.size() != previous.xstate.size())
		throw std::runtime_error("native XSTATE size does not match the host");
	iovec buffer{const_cast<uint8_t *>(context.xstate.data()), context.xstate.size()};
	if (ptrace(PTRACE_SETREGSET, state->child->pid, reinterpret_cast<void *>(NT_X86_XSTATE), &buffer) == -1)
		throw std::runtime_error("cannot restore native XSTATE");
	try {
		trace(PTRACE_SETREGS, state->child->pid, const_cast<user_regs_struct *>(&context.registers));
	} catch (...) {
		iovec rollback{const_cast<uint8_t *>(previous.xstate.data()), previous.xstate.size()};
		if (ptrace(PTRACE_SETREGSET, state->child->pid, reinterpret_cast<void *>(NT_X86_XSTATE), &rollback) == -1)
			state->child->stop();
		throw;
	}
}

std::vector<uint8_t> NativeProcess::read_memory(uint64_t address, size_t size) const
{
	state->require_stopped();
	if (!state->covers(address, size, PROT_READ))
		throw std::runtime_error("native read exceeds readable guest memory");
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
	uint64_t a3, uint64_t a4, uint64_t a5)
{
	state->require_stopped();
	const auto saved = context();
	auto &child = *state->child;
	child.set_timeout(std::chrono::seconds(2));
	uint64_t result = 0;
	try {
		result = child.syscall(number, a1, a2, a3, a4, a5);
	} catch (...) {
		try {
			if (child.pid == -1 || context().registers.rip != child.gate + 4)
				throw std::runtime_error("native memory operation lost its gate");
			set_context(saved);
		} catch (...) {
			child.stop();
			throw;
		}
		throw;
	}
	try {
		set_context(saved);
	} catch (...) {
		child.stop();
		throw;
	}
	return result;
}

static void memory_range(uint64_t address, size_t size, int protection, uint64_t limit)
{
	if (!size || size % 4096 || size > 1024 * 1024 * 1024 || address % 4096 ||
		address >= limit || size > limit - address || (protection & ~(PROT_READ | PROT_WRITE | PROT_EXEC)))
		throw std::runtime_error("invalid native memory range or protection");
}

uint64_t NativeProcess::map_memory(size_t size, int protection, uint64_t address)
{
	state->require_stopped();
	memory_range(address, size, protection, state->limit());
	state->mappings.reserve(state->mappings.size() + 1);
	state->allocations.reserve(state->allocations.size() + 1);
	const auto mapped = memory_syscall(SYS_mmap, address, size, static_cast<uint64_t>(protection),
		MAP_PRIVATE | MAP_ANONYMOUS | (address ? MAP_FIXED_NOREPLACE : state->mode == NativeMode::x86 ? MAP_32BIT : 0), uint64_t(-1));
	if ((address && mapped != address) || mapped >= state->limit() || size > state->limit() - mapped) {
		state->child->stop();
		throw std::runtime_error("host returned an invalid native allocation address");
	}
	state->mappings.push_back({mapped, size, 0, protection});
	state->allocations.emplace_back(mapped, size);
	return mapped;
}

void NativeProcess::protect_memory(uint64_t address, size_t size, int protection)
{
	state->require_stopped();
	memory_range(address, size, protection, state->limit());
	const auto owned = std::find_if(state->allocations.begin(), state->allocations.end(), [&](const auto &allocation) {
		return address >= allocation.first && address - allocation.first < allocation.second &&
			size <= allocation.second - (address - allocation.first);
	});
	if (owned == state->allocations.end())
		throw std::runtime_error("native protection range is outside a dynamic allocation");
	std::vector<ImageMapping> updated;
	updated.reserve(state->mappings.size() + 2);
	const uint64_t end = address + size;
	for (const auto &mapping : state->mappings) {
		const uint64_t last = mapping.address + mapping.size;
		if (last <= address || mapping.address >= end) {
			updated.push_back(mapping);
			continue;
		}
		if (mapping.address < address)
			updated.push_back({mapping.address, address - mapping.address, 0, mapping.protection});
		const uint64_t first = std::max(mapping.address, address);
		updated.push_back({first, std::min(last, end) - first, 0, protection});
		if (last > end)
			updated.push_back({end, last - end, 0, mapping.protection});
	}
	memory_syscall(SYS_mprotect, address, size, static_cast<uint64_t>(protection));
	state->mappings.swap(updated);
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
	std::erase_if(state->mappings, [&](const auto &mapping) { return mapping.address >= address && mapping.address < end; });
	std::erase_if(state->api_traps, [&](const auto &trap) { return trap.first >= address && trap.first < end; });
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
	for (const auto &mapping : state->mappings)
		if (address < mapping.address+mapping.size && mapping.address < end)
			return false;
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
	state->mappings.reserve(state->mappings.size() + mappings.size() + 1);
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
		state->mappings.insert(state->mappings.end(), mappings.begin(), mappings.end());
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
	std::erase_if(state->mappings, [&](const auto &mapping) { return mapping.address >= address && mapping.address < end; });
	std::erase_if(state->api_traps, [&](const auto &trap) { return trap.first >= address && trap.first < end; });
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
		state->debug_print_fault, state->pending_cleanup, state->stack_top};
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
}

NativeThreadState NativeProcess::new_thread(uint64_t stack_top, uint64_t teb) const
{
	state->require_stopped();
	if (state->mode != NativeMode::x64)
		throw std::runtime_error("native guest threads are x64 only");
	NativeThreadState thread{};
	thread.context = context();
	thread.context.registers.gs_base = teb;
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
	if (state->mode != NativeMode::x86 || base > 0xfffff000ULL || base % 4096)
		throw std::runtime_error("native TEB descriptor requires an x86 process and a page-aligned 32-bit address");
	// struct user_desc: entry, base, limit, flags (32-bit segment, data, byte granularity, usable).
	std::vector<uint8_t> descriptor(16);
	const uint32_t fields[] = {0, uint32_t(base), 0xfff, 0x41};
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
	// LDT index 0, table indicator 1, requested privilege level 3.
	state->fs_selector = 7;
	state->fs_base = base;
}

void NativeProcess::add_api_trap(uint64_t address, uint32_t callee_cleanup)
{
	state->require_stopped();
	if (!state->covers(address, 1, PROT_EXEC) || read_memory(address, 1)[0] != 0xcc)
		throw std::runtime_error("native API trap must be an executable INT3");
	if (state->mode == NativeMode::x86 && (address >= state->limit() || callee_cleanup % 4))
		throw std::runtime_error("native x86 API trap requires a 32-bit address and dword-aligned cleanup");
	state->api_traps[address] = callee_cleanup;
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
	if (!state->active_call || !state->awaiting_api)
		throw std::runtime_error("native callback requires a pending API call");
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
	if (!state->active_call || state->awaiting_api)
		throw std::runtime_error("native process has no resumable call or awaits an API response");
	auto &child = *state->child;
	child.set_timeout(timeout);
	int status;
	user_regs_struct registers{};
	int signal;
	for (;;) {
		// SYSEMU blocks host syscall dispatch; invalid syscall gates can fault first. Diagnostics may single-step instead.
		trace(state->steps_left ? PTRACE_SINGLESTEP : PTRACE_SYSEMU, child.pid);
		state->stopped = false;
		status = child.wait();
		if (status == -1) {
			child.stop();
			return {NativeStop::timeout, 0, 0, 0};
		}
		if (!WIFSTOPPED(status))
			throw std::runtime_error("native guest exited outside the runtime boundary");
		state->stopped = true;
		trace(PTRACE_GETREGS, child.pid, &registers);
		signal = WSTOPSIG(status);
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
	trace(PTRACE_GETSIGINFO, child.pid, &info);
	state->debug_print_fault=signal==SIGSEGV && info.si_code==SI_KERNEL && registers.rax==1;
	if (signal == SIGTRAP && info.si_code == TRAP_HWBKPT) {
		// Reading the stop reason is enough; DR6 must be cleared or the next trap reports a stale cause.
		ptrace(PTRACE_POKEUSER, child.pid, reinterpret_cast<void *>(offsetof(struct user, u_debugreg) + 6 * sizeof(unsigned long)), nullptr);
	}
	const bool breakpoint = signal == SIGTRAP && (info.si_code == TRAP_BRKPT || info.si_code == SI_KERNEL);
	const bool x86 = state->mode == NativeMode::x86;
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

std::vector<uint64_t> NativeProcess::api_arguments(size_t count) const
{
	state->require_stopped();
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

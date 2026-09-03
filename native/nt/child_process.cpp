#include "child_process.h"

#include "text.h"

#include <atomic>
#include <map>
#include <mutex>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <vector>
#include <cstdlib>
#include <sstream>
#include <string>
#include <sys/mman.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace raven {

namespace {

std::atomic<int> live{0};
std::mutex known_mutex;
std::map<pid_t, std::weak_ptr<ProcessObject>> known;

}

bool ProcessObject::exited() const
{
	reap();
	return done;
}

uint32_t ProcessObject::exit_code() const
{
	reap();
	return code;
}

void ProcessObject::reap() const
{
	if (done)
		return;
	int status = 0;
	pid_t result;
	do result = ::waitpid(pid, &status, WNOHANG); while (result < 0 && errno == EINTR);
	if (result == 0)
		return;
	done = true;
	--live;
	if (result < 0)
		code = 0;
	else if (killed)
		code = requested;
	else if (WIFEXITED(status))
		code = uint32_t(WEXITSTATUS(status));
	else
		code = 0xc0000005U;
}

void ProcessObject::terminate(uint32_t exit)
{
	if (exited())
		return;
	requested = exit;
	killed = true;
	::kill(pid, SIGKILL);
}

std::shared_ptr<ProcessObject> spawn_child(const ChildLaunch &launch, uint32_t &error)
{
	char self[4096];
	const auto length = ::readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (length <= 0) {
		error = 5;
		return nullptr;
	}
	self[length] = 0;
	// What the parent was started with, such as the window system and the time budget, applies to its children.
	std::vector<std::string> arguments{self, "--run-process", "--execution=native"};
	if (const char *options = std::getenv("RAVEN_CHILD_OPTIONS")) {
		std::istringstream words(options);
		for (std::string word; words >> word;)
			arguments.push_back(word);
	}
	arguments.push_back("--stdio=inherit");
	int inherited[2] = {-1, -1};
	if (!launch.environment.empty()) {
		// The block travels in an anonymous file the child reads once and closes.
		const int file = ::memfd_create("raven-environment", 0);
		if (file < 0) {
			error = 8;
			return nullptr;
		}
		const auto bytes = reinterpret_cast<const char *>(launch.environment.data());
		const size_t size = launch.environment.size() * 2;
		for (size_t done = 0; done < size;) {
			const auto count = ::write(file, bytes + done, size - done);
			if (count <= 0) {
				::close(file);
				error = 8;
				return nullptr;
			}
			done += size_t(count);
		}
		::lseek(file, 0, SEEK_SET);
		inherited[0] = file;
		arguments.push_back("--environment-fd=" + std::to_string(file));
	}
	int gate_pair[2] = {-1, -1};
	if (launch.suspended) {
		if (::pipe2(gate_pair, O_CLOEXEC)) {
			if (inherited[0] >= 0)
				::close(inherited[0]);
			error = 8;
			return nullptr;
		}
		// Only the reading end goes to the child; the writing end stays with the parent.
		::fcntl(gate_pair[0], F_SETFD, 0);
		arguments.push_back("--suspended-fd=" + std::to_string(gate_pair[0]));
	}
	arguments.push_back("--command-line=" + to_utf8(launch.command_line));
	arguments.push_back("--directory=" + to_utf8(launch.directory));
	arguments.push_back(launch.image.string());
	std::vector<char *> argv;
	for (auto &argument : arguments)
		argv.push_back(argument.data());
	argv.push_back(nullptr);

	const auto release_extra = [&] {
		if (inherited[0] >= 0)
			::close(inherited[0]);
		if (gate_pair[0] >= 0)
			::close(gate_pair[0]);
	};
	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	// Duplicating onto a descriptor that still has to be read as a source would lose it: move every source out of the way first.
	int moved[3];
	for (int index = 0; index < 3; ++index) {
		moved[index] = ::fcntl(launch.standard[index], F_DUPFD_CLOEXEC, 10);
		if (moved[index] < 0) {
			for (int back = 0; back < index; ++back)
				::close(moved[back]);
			release_extra();
			if (gate_pair[1] >= 0)
				::close(gate_pair[1]);
			posix_spawn_file_actions_destroy(&actions);
			error = 6;
			return nullptr;
		}
	}
	for (int index = 0; index < 3; ++index)
		posix_spawn_file_actions_adddup2(&actions, moved[index], index);
	posix_spawnattr_t attributes;
	posix_spawnattr_init(&attributes);
	sigset_t none, all;
	sigemptyset(&none);
	sigfillset(&all);
	posix_spawnattr_setsigmask(&attributes, &none);
	posix_spawnattr_setsigdefault(&attributes, &all);
	posix_spawnattr_setflags(&attributes, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF);
	pid_t child = 0;
	const int status = ::posix_spawn(&child, self, &actions, &attributes, argv.data(), environ);
	posix_spawnattr_destroy(&attributes);
	posix_spawn_file_actions_destroy(&actions);
	for (int index = 0; index < 3; ++index)
		::close(moved[index]);
	release_extra();
	if (status) {
		if (gate_pair[1] >= 0)
			::close(gate_pair[1]);
		error = status == ENOENT ? 2 : status == ENOMEM ? 8 : 5;
		return nullptr;
	}
	if (launch.gate)
		*launch.gate = gate_pair[1];
	++live;
	auto object = std::make_shared<ProcessObject>(child);
	object->name = from_utf8(launch.image.filename().string());
	{
		std::lock_guard lock(known_mutex);
		known[child] = object;
	}
	return object;
}

std::shared_ptr<ProcessObject> find_child(pid_t pid)
{
	std::lock_guard lock(known_mutex);
	const auto found = known.find(pid);
	return found == known.end() ? nullptr : found->second.lock();
}

std::vector<std::shared_ptr<ProcessObject>> live_children()
{
	std::vector<std::shared_ptr<ProcessObject>> result;
	std::lock_guard lock(known_mutex);
	for (const auto &[pid, weak] : known)
		if (const auto object = weak.lock(); object && !object->exited())
			result.push_back(object);
	return result;
}

bool children_running()
{
	return live.load() > 0;
}

namespace {

std::atomic<int> host_waits{0};

}

HostWait::HostWait() { ++host_waits; }
HostWait::~HostWait() { --host_waits; }

bool host_events_pending()
{
	return live.load() > 0 || host_waits.load() > 0;
}

}

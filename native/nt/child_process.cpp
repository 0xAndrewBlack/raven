#include "child_process.h"

#include "text.h"

#include <atomic>
#include <cerrno>
#include <csignal>
#include <fcntl.h>
#include <vector>
#include <cstdlib>
#include <sstream>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

namespace raven {

namespace {

std::atomic<int> live{0};

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
	arguments.push_back("--command-line=" + to_utf8(launch.command_line));
	arguments.push_back("--directory=" + to_utf8(launch.directory));
	arguments.push_back(launch.image.string());
	std::vector<char *> argv;
	for (auto &argument : arguments)
		argv.push_back(argument.data());
	argv.push_back(nullptr);

	posix_spawn_file_actions_t actions;
	posix_spawn_file_actions_init(&actions);
	// Duplicating onto a descriptor that still has to be read as a source would lose it: move every source out of the way first.
	int moved[3];
	for (int index = 0; index < 3; ++index) {
		moved[index] = ::fcntl(launch.standard[index], F_DUPFD_CLOEXEC, 10);
		if (moved[index] < 0) {
			for (int back = 0; back < index; ++back)
				::close(moved[back]);
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
	if (status) {
		error = status == ENOENT ? 2 : status == ENOMEM ? 8 : 5;
		return nullptr;
	}
	++live;
	return std::make_shared<ProcessObject>(child);
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

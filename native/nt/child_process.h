#pragma once

#include "objects.h"

#include <filesystem>
#include <string>
#include <sys/types.h>

namespace raven {

// A process that Raven started for the guest: another instance of the runtime that runs the child program on its own.
class ProcessObject : public KernelObject {
public:
	explicit ProcessObject(pid_t pid) : pid(pid) {}
	// Waiting for a process succeeds once it has ended; the host reports that, not another guest thread.
	int signaled(uint32_t) const override { return exited() ? 1 : 0; }
	bool exited() const;
	// STILL_ACTIVE (259) while the process runs.
	uint32_t exit_code() const;
	// Ends the process the way TerminateProcess does, with the given exit code.
	void terminate(uint32_t code);
	const pid_t pid;

private:
	void reap() const;
	mutable bool done = false;
	mutable uint32_t code = 259;
	uint32_t requested = 0;
	bool killed = false;
};

// The main thread of a child process: signaled when the process has ended.
class ChildThreadObject : public KernelObject {
public:
	explicit ChildThreadObject(std::shared_ptr<ProcessObject> process) : process(std::move(process)) {}
	int signaled(uint32_t) const override { return process->exited() ? 1 : 0; }

private:
	std::shared_ptr<ProcessObject> process;
};

struct ChildLaunch {
	std::filesystem::path image;
	std::u16string command_line;
	std::u16string directory;
	// Descriptors that become the child's standard input, output and error.
	int standard[3] = {0, 1, 2};
};

// Starts the child; null with the Windows error in `error` when the host could not.
std::shared_ptr<ProcessObject> spawn_child(const ChildLaunch &launch, uint32_t &error);
// True while any child has not been reaped yet: guest threads then wait on the host rather than on each other.
bool children_running();
// A guest thread that waits for something only the host can deliver, such as network data, counts for as long as the object lives.
class HostWait {
public:
	HostWait();
	~HostWait();
	HostWait(const HostWait &) = delete;
	HostWait &operator=(const HostWait &) = delete;
};
// True while a child runs or a guest thread waits on the host: waiting threads are then not deadlocked.
bool host_events_pending();

}

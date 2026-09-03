#pragma once

#include "child_process.h"
#include "objects.h"

#include <deque>
#include <functional>
#include <memory>
#include <vector>

namespace raven {

struct CompletionPacket {
	uint64_t bytes = 0, key = 0, overlapped = 0;
	// The Windows error of the operation, zero when it succeeded.
	uint32_t status = 0;
};

// An I/O completion port: a queue of finished operations that threads take from.
class CompletionPort : public KernelObject {
public:
	void post(const CompletionPacket &packet) { packets.push_back(packet); }
	bool take(CompletionPacket &packet)
	{
		if (packets.empty())
			return false;
		packet = packets.front();
		packets.pop_front();
		return true;
	}
	bool empty() const { return packets.empty(); }

private:
	std::deque<CompletionPacket> packets;
};

// Operations that were started and cannot finish yet. Each one is asked again whenever the process looks for completions, and drops out
// once it reports that it has finished.
class Reactor {
public:
	using Operation = std::function<bool()>;
	// A pending operation counts as work only the host can finish, so waiting threads are not taken for deadlocked.
	void add(Operation operation) { operations.push_back({std::move(operation), std::make_unique<HostWait>()}); }
	// Gives every pending operation a chance to finish; true when any did.
	bool poll()
	{
		bool finished = false;
		for (size_t index = 0; index < operations.size();) {
			if (operations[index].first()) {
				operations.erase(operations.begin() + ptrdiff_t(index));
				finished = true;
			} else {
				++index;
			}
		}
		return finished;
	}
	size_t pending() const { return operations.size(); }

private:
	std::vector<std::pair<Operation, std::unique_ptr<HostWait>>> operations;
};

}

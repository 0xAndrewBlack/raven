#pragma once

#include "completion_port.h"
#include "file_objects.h"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <sys/socket.h>
#include <vector>

namespace raven {

struct KernelContext;
class ApiCall;
class ApiRegistry;

// What every instance of one named pipe shares: the listening socket that clients connect to.
struct PipeListener {
	~PipeListener()
	{
		if (descriptor >= 0)
			::close(descriptor);
	}
	int descriptor = -1;
	int type = SOCK_STREAM;
	uint32_t maximum = 255, instances = 0;
	std::string address;
};

// One end of a pipe. A server end is created listening and becomes connected when a client opens the pipe; a client end, and both ends
// of an anonymous pipe, are connected from the start. The data moves through a host socket that stays blocking for the program that
// shares it, so every transfer asks for non-blocking behavior call by call.
class PipeObject : public FileObject {
public:
	PipeObject(int descriptor, uint32_t access, uint32_t flags) : FileObject(descriptor, access, false, std::filesystem::path(), std::u16string(), flags) {}
	~PipeObject() override;
	bool describe(InheritedHandle &record) const override
	{
		// A server end that no client has opened has no connection to hand over.
		if (descriptor < 0)
			return false;
		record.kind = "pipe";
		record.descriptor = descriptor;
		record.access = access;
		record.flags = flags;
		record.bits = (message_mode ? 1U : 0U) | (server ? 2U : 0U);
		record.text = name;
		return true;
	}
	bool overlapped() const { return flags & 0x40000000U; }
	std::shared_ptr<PipeListener> listener;
	bool server = false, connected = false, message_mode = false, inherit = false;
	// FILE_SKIP_COMPLETION_PORT_ON_SUCCESS: a transfer that finishes inside the call does not also queue a completion.
	bool skip_port_on_success = false, skip_event_on_success = false;
	std::shared_ptr<CompletionPort> port;
	uint64_t key = 0;
	std::u16string name;
	// The unread rest of a message that did not fit the buffer of the read that took it.
	std::vector<uint8_t> carry;
};

// An overlapped operation that has not finished: the pipe it runs on, so closing or cancelling can end it.
struct PendingIo {
	std::weak_ptr<PipeObject> pipe;
	uint64_t overlapped = 0;
	bool cancelled = false;
};

struct PipeState {
	std::map<std::string, std::weak_ptr<PipeListener>> listeners;
	std::vector<std::shared_ptr<PendingIo>> pending;
};

// A server end whose client has opened the pipe takes that connection: true when the end is connected.
bool ensure_pipe_connected(PipeObject &pipe);
void register_pipe_api(ApiRegistry &registry, KernelContext &context);
// The Windows form of a pipe path, "\\.\pipe\name": the name without the prefix, or nothing for any other path.
std::optional<std::u16string> pipe_name_of(std::u16string_view path);
// CreateFile on a pipe path; false when the path names no pipe.
bool open_pipe_client(KernelContext &context, ApiCall &call, std::u16string_view path, uint32_t access, uint32_t flags);
// ReadFile and WriteFile on a pipe handle; false when the handle is no pipe.
bool transfer_pipe(KernelContext &context, ApiCall &call, bool reading);

}

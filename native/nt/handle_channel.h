#pragma once

#include "inherit.h"

#include <cstdint>
#include <map>
#include <memory>
#include <optional>

namespace raven {

class KernelObject;
class NativeObjects;
class NativeThreads;

// The first handle value a process gives to a handle it hands to another one, and the first value it expects from that one. The
// ranges differ per direction and sit above anything a process numbers for itself.
constexpr uint64_t handle_range_to_child = 0x40000000, handle_range_to_parent = 0x50000000;

// A socket between a process and one of its children that carries handles after the child started (DuplicateHandle into or out of
// the other process). A handle sent over arrives as a descriptor with the record that rebuilds the object, and the receiver takes it
// in when it first looks the value up. A handle asked for is answered by the other process the next time it schedules its threads.
class HandleChannel {
public:
	HandleChannel(int descriptor, uint64_t first_value) : descriptor(descriptor), next(first_value) {}
	~HandleChannel();
	HandleChannel(const HandleChannel &) = delete;
	HandleChannel &operator=(const HandleChannel &) = delete;
	// Sends a handle the described object stands behind; the value it will have in the other process, or zero on failure.
	uint64_t send(InheritedHandle record, uint32_t inherit);
	// Asks the other process for the object behind one of its handles, closing it there when `close_source` is set; null when the
	// other process has no such handle or it cannot travel. `access` receives the rights the handle carried.
	std::shared_ptr<KernelObject> fetch(NativeObjects &objects, NativeThreads &threads, uint64_t value, bool close_source, uint32_t &access);
	// Takes in the handles that have arrived, answers the requests and keeps the answers to requests of this side.
	void receive(NativeObjects &objects);

private:
	bool send_frame(const InheritedHandle &record, int shared);
	int descriptor;
	uint64_t next;
	uint64_t next_request = 1;
	std::map<uint64_t, std::optional<InheritedHandle>> answers;
};

// The channel a child keeps to its parent: it comes from the descriptor the parent passed.
void set_parent_channel(int descriptor);
HandleChannel *parent_channel();
// Makes a child's channel known so lookups of unknown handle values drain it.
void add_child_channel(HandleChannel *channel);
void remove_child_channel(HandleChannel *channel);
// Takes in whatever the other processes have sent and answers what they asked.
void receive_handles(NativeObjects &objects);

}

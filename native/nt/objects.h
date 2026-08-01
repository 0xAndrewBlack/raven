#pragma once

#include <chrono>
#include <condition_variable>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <cstdint>

namespace raven {

// Base of the kernel objects that are not events: files, searches, mappings, threads and the like.
class KernelObject {
public:
	virtual ~KernelObject() = default;
	// Waiting: 1 when a wait by the given thread would succeed now, 0 when it would block, -1 for objects that cannot be waited on.
	virtual int signaled(uint32_t thread) const { (void)thread; return -1; }
	// Runs when a wait succeeds: auto-reset events clear, mutexes change owner, semaphores count down.
	virtual void consume(uint32_t thread) { (void)thread; }
};

struct NativeObjectResult {
	uint64_t value = 0;
	uint32_t status = 0;
	bool runtime_timeout = false;
};

// Process handle identities refer to shared object state, rather than copying it.
class NativeObjects {
public:
	explicit NativeObjects(size_t limit = 10000) : limit(limit) {}
	NativeObjects(const NativeObjects &) = delete;
	NativeObjects &operator=(const NativeObjects &) = delete;
	NativeObjectResult create_event(uint32_t access, uint32_t type, bool signaled);
	NativeObjectResult inherit_file(int descriptor);
	// Reads from an inherited standard handle; the value is the byte count, zero at the end of the input.
	NativeObjectResult read_file(uint64_t handle,std::span<uint8_t> into);
	NativeObjectResult file_type(uint64_t handle) const;
	NativeObjectResult write_file(uint64_t handle, std::span<const uint8_t> bytes);
	uint32_t close(uint64_t handle);
	// Generic objects share the handle namespace of events and inherited files.
	NativeObjectResult add_object(std::shared_ptr<KernelObject> object);
	std::shared_ptr<KernelObject> object(uint64_t handle) const;
	template<typename T> std::shared_ptr<T> object_as(uint64_t handle) const { return std::dynamic_pointer_cast<T>(object(handle)); }
	// Waiting state of any handle kind (see KernelObject::signaled); -2 when the handle does not exist.
	int signaled(uint64_t handle, uint32_t thread) const;
	void consume(uint64_t handle, uint32_t thread);
	// Duplicates a handle onto the same object (DuplicateHandle within the process).
	NativeObjectResult duplicate(uint64_t handle);
	NativeObjectResult set_event(uint64_t handle, bool signaled);
	NativeObjectResult query_event(uint64_t handle);
	NativeObjectResult wait(uint64_t handle, std::optional<int64_t> timeout,
		std::chrono::steady_clock::time_point deadline);
	size_t count() const;
	size_t waiting(uint64_t handle) const;

private:
	struct Event {
		struct Waiter { bool ready = false; };
		std::mutex mutex;
		std::condition_variable changed;
		uint32_t type;
		bool signaled;
		std::deque<std::shared_ptr<Waiter>> waiters;
		Event(uint32_t type, bool signaled) : type(type), signaled(signaled) {}
	};
	struct File {
		int descriptor;
		uint32_t type;
		File(int descriptor,uint32_t type) : descriptor(descriptor),type(type) {}
		~File();
	};
	struct Handle { std::shared_ptr<Event> event; uint32_t access; std::shared_ptr<File> file; std::shared_ptr<KernelObject> generic = {}; };
	mutable std::mutex mutex;
	std::map<uint64_t,Handle> handles;
	uint64_t next = 0x100;
	size_t limit;
	std::pair<std::shared_ptr<Event>,uint32_t> event(uint64_t handle, uint32_t access) const;
	std::shared_ptr<File> file(uint64_t handle) const;
};

}

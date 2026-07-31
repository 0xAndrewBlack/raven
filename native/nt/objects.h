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
	NativeObjectResult file_type(uint64_t handle) const;
	NativeObjectResult write_file(uint64_t handle, std::span<const uint8_t> bytes);
	uint32_t close(uint64_t handle);
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
	struct Handle { std::shared_ptr<Event> event; uint32_t access; std::shared_ptr<File> file; };
	mutable std::mutex mutex;
	std::map<uint64_t,Handle> handles;
	uint64_t next = 0x100;
	size_t limit;
	std::pair<std::shared_ptr<Event>,uint32_t> event(uint64_t handle, uint32_t access) const;
	std::shared_ptr<File> file(uint64_t handle) const;
};

}

#pragma once

#include "objects.h"

namespace raven {

std::optional<uint32_t> event_access(uint32_t requested);

class EventObject : public KernelObject {
public:
	EventObject(uint32_t type, bool signaled) : type(type), local_signaled(signaled) {}
	explicit EventObject(int descriptor);
	~EventObject() override;
	int signaled(uint32_t thread) const override;
	void consume(uint32_t thread) override;
	bool try_consume(uint32_t thread) override;
	int set_state(bool signaled) override;
	bool describe(InheritedHandle &record) const override;
	std::u16string_view type_name() const override { return u"Event"; }

private:
	friend class NativeObjects;
	struct Shared;
	struct Waiter { bool ready = false; };
	mutable std::mutex mutex;
	mutable std::condition_variable changed;
	uint32_t type;
	bool local_signaled;
	std::deque<std::shared_ptr<Waiter>> waiters;
	mutable int descriptor = -1;
	mutable Shared *shared = nullptr;
	bool is_set() const;
	bool take();
};

}

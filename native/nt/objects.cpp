#include "objects.h"

#include <algorithm>
#include <limits>

namespace raven {

static constexpr uint32_t invalid_handle=0xc0000008U, denied=0xc0000022U;

static std::optional<uint32_t> access_mask(uint32_t access)
{
	uint32_t mapped=access & 0x001f0003U;
	if (access & 0x80000000U) mapped|=0x120001;
	if (access & 0x40000000U) mapped|=0x120002;
	if (access & 0x20000000U) mapped|=0x120000;
	if (access & 0x10000000U) mapped|=0x1f0003;
	if (access & 0x02000000U) mapped|=0x1f0003;
	if (access & ~0xf21f0003U)
		return std::nullopt;
	return mapped;
}

NativeObjectResult NativeObjects::create_event(uint32_t access, uint32_t type, bool signaled)
{
	if (type>1)
		return {0,0xc000000dU};
	const auto mapped=access_mask(access);
	if (!mapped)
		return {0,0xc00000bbU};
	std::lock_guard lock(mutex);
	if (handles.size()>=limit || next>UINT32_MAX-4)
		return {0,0xc000009aU};
	const auto handle=next;
	handles.emplace(handle,Handle{std::make_shared<Event>(type,signaled),*mapped,{}});
	next+=4;
	return {handle};
}

std::pair<std::shared_ptr<NativeObjects::Event>,uint32_t> NativeObjects::event(uint64_t handle, uint32_t access) const
{
	std::lock_guard lock(mutex);
	const auto found=handles.find(handle);
	if (found==handles.end()) return {nullptr,invalid_handle};
	if (!found->second.event) return {nullptr,0xc0000024U};
	if ((found->second.access & access)!=access) return {nullptr,denied};
	return {found->second.event,0};
}

uint32_t NativeObjects::close(uint64_t handle)
{
	std::lock_guard lock(mutex);
	return handles.erase(handle) ? 0 : invalid_handle;
}

NativeObjectResult NativeObjects::set_event(uint64_t handle, bool signaled)
{
	const auto [object,status]=event(handle,2);
	if (status) return {0,status};
	std::lock_guard lock(object->mutex);
	const auto previous=object->signaled;
	object->signaled=signaled;
	if (signaled) {
		if (object->type==0) {
			for (const auto &waiter : object->waiters) waiter->ready=true;
			object->waiters.clear();
		} else if (!object->waiters.empty()) {
			object->waiters.front()->ready=true;
			object->waiters.pop_front();
			object->signaled=false;
		}
		object->changed.notify_all();
	}
	return {uint64_t(previous)};
}

NativeObjectResult NativeObjects::query_event(uint64_t handle)
{
	const auto [object,status]=event(handle,1);
	if (status) return {0,status};
	std::lock_guard lock(object->mutex);
	return {uint64_t(object->type) | (uint64_t(object->signaled)<<32)};
}

NativeObjectResult NativeObjects::wait(uint64_t handle, std::optional<int64_t> timeout,
	std::chrono::steady_clock::time_point deadline)
{
	const auto [object,status]=event(handle,0x100000);
	if (status) return {0,status};
	if (timeout && *timeout>0) return {0,0xc00000bbU};
	std::unique_lock lock(object->mutex);
	if (!object->signaled) {
		if (timeout && !*timeout) return {0,0x102};
		if (object->waiters.size()>=10000) return {0,0xc000009aU};
		const auto now=std::chrono::steady_clock::now();
		auto expires=std::chrono::steady_clock::time_point::max();
		if (timeout) {
			const auto ticks=uint64_t(-(*timeout+1))+1;
			const auto room=std::chrono::duration_cast<std::chrono::nanoseconds>(expires-now).count();
			if (ticks<=uint64_t(room)/100)
				expires=now+std::chrono::nanoseconds(ticks*100);
		}
		const auto waiter=std::make_shared<Event::Waiter>();
		object->waiters.push_back(waiter);
		if (!object->changed.wait_until(lock,std::min(expires,deadline),[&] { return waiter->ready; })) {
			std::erase(object->waiters,waiter);
			return expires<=deadline ? NativeObjectResult{0,0x102} : NativeObjectResult{0,0,true};
		}
		return {};
	}
	if (object->type==1) object->signaled=false;
	return {};
}

size_t NativeObjects::count() const
{
	std::lock_guard lock(mutex);
	return handles.size();
}

size_t NativeObjects::waiting(uint64_t handle) const
{
	const auto [object,status]=event(handle,0);
	if (status) return 0;
	std::lock_guard lock(object->mutex);
	return object->waiters.size();
}

}

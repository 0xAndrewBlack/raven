#include "objects.h"
#include "api.h"

#include <cstdio>
#include <cstdlib>

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

uint64_t NativeObjects::take()
{
	while (handles.contains(next)) next += 4;
	const auto value = next;
	next += 4;
	static const bool traced = std::getenv("RAVEN_TRACE_HANDLES") != nullptr;
	if (traced) std::fprintf(stderr, "handle %llx made by %s\n", static_cast<unsigned long long>(value), api_in_progress);
	return value;
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
	const auto handle=take();
	handles.emplace(handle,Handle{std::make_shared<Event>(type,signaled),*mapped,{}});
	return {handle};
}

NativeObjectResult NativeObjects::create_named_event(const std::u16string &name, uint32_t access, uint32_t type, bool signaled, bool &existed)
{
	existed=false;
	if (type>1)
		return {0,0xc000000dU};
	const auto mapped=access_mask(access);
	if (!mapped)
		return {0,0xc00000bbU};
	std::u16string key=name;
	for (auto &character : key) if (character>=u'a' && character<=u'z') character=char16_t(character-(u'a'-u'A'));
	std::lock_guard lock(mutex);
	if (handles.size()>=limit || next>UINT32_MAX-4)
		return {0,0xc000009aU};
	std::shared_ptr<Event> shared;
	if (const auto found=named_events.find(key); found!=named_events.end()) shared=found->second.lock();
	existed=shared!=nullptr;
	if (!shared) {
		shared=std::make_shared<Event>(type,signaled);
		named_events[key]=shared;
	}
	const auto handle=take();
	handles.emplace(handle,Handle{shared,*mapped,{}});
	return {handle};
}

NativeObjectResult NativeObjects::open_named_event(const std::u16string &name, uint32_t access)
{
	const auto mapped=access_mask(access);
	if (!mapped)
		return {0,0xc00000bbU};
	std::u16string key=name;
	for (auto &character : key) if (character>=u'a' && character<=u'z') character=char16_t(character-(u'a'-u'A'));
	std::lock_guard lock(mutex);
	const auto found=named_events.find(key);
	const auto shared=found==named_events.end() ? nullptr : found->second.lock();
	if (!shared) return {0,0xc0000034U};
	if (handles.size()>=limit || next>UINT32_MAX-4)
		return {0,0xc000009aU};
	const auto handle=take();
	handles.emplace(handle,Handle{shared,*mapped,{}});
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

NativeObjectResult NativeObjects::add_object(std::shared_ptr<KernelObject> object)
{
	std::lock_guard lock(mutex);
	if (handles.size()>=limit || next>UINT32_MAX-4)
		return {0,0xc000009aU};
	const auto handle=take();
	handles.emplace(handle,Handle{{},0x1f0003,{},std::move(object)});
	return {handle};
}

std::shared_ptr<KernelObject> NativeObjects::object(uint64_t handle) const
{
	std::lock_guard lock(mutex);
	const auto found=handles.find(handle);
	return found==handles.end() ? nullptr : found->second.generic;
}

int NativeObjects::signaled(uint64_t handle, uint32_t thread) const
{
	std::shared_ptr<Event> event;
	std::shared_ptr<KernelObject> generic;
	{
		std::lock_guard lock(mutex);
		const auto found=handles.find(handle);
		if (found==handles.end()) return -2;
		event=found->second.event;
		generic=found->second.generic;
	}
	if (generic) return generic->signaled(thread);
	if (event) {
		std::lock_guard lock(event->mutex);
		return event->signaled ? 1 : 0;
	}
	return -1;
}

void NativeObjects::consume(uint64_t handle, uint32_t thread)
{
	std::shared_ptr<Event> event;
	std::shared_ptr<KernelObject> generic;
	{
		std::lock_guard lock(mutex);
		const auto found=handles.find(handle);
		if (found==handles.end()) return;
		event=found->second.event;
		generic=found->second.generic;
	}
	if (generic) generic->consume(thread);
	else if (event) {
		std::lock_guard lock(event->mutex);
		if (event->type==1) event->signaled=false;
	}
}

NativeObjectResult NativeObjects::duplicate(uint64_t handle, std::optional<uint32_t> access)
{
	std::lock_guard lock(mutex);
	const auto found=handles.find(handle);
	if (found==handles.end())
		return {0,invalid_handle};
	if (handles.size()>=limit || next>UINT32_MAX-4)
		return {0,0xc000009aU};
	const auto copy=take();
	// The copy is a new handle: it inherits only when the caller says so.
	auto duplicate_handle=found->second;
	duplicate_handle.inherit=false;
	if (access) duplicate_handle.access=*access;
	handles.emplace(copy,std::move(duplicate_handle));
	return {copy};
}

uint32_t NativeObjects::access_of(uint64_t handle) const
{
	std::lock_guard lock(mutex);
	const auto found=handles.find(handle);
	return found==handles.end() ? 0 : found->second.access;
}

void NativeObjects::set_access(uint64_t handle, uint32_t access)
{
	std::lock_guard lock(mutex);
	if (const auto found=handles.find(handle); found!=handles.end())
		found->second.access=access;
}

void NativeObjects::set_inherit(uint64_t handle, bool inherit)
{
	std::lock_guard lock(mutex);
	if (const auto found=handles.find(handle); found!=handles.end())
		found->second.inherit=inherit;
}

bool NativeObjects::inherit(uint64_t handle) const
{
	std::lock_guard lock(mutex);
	const auto found=handles.find(handle);
	return found!=handles.end() && found->second.inherit;
}

std::vector<uint64_t> NativeObjects::inheritable() const
{
	std::lock_guard lock(mutex);
	std::vector<uint64_t> result;
	for (const auto &[value,handle] : handles)
		if (handle.inherit)
			result.push_back(value);
	return result;
}

bool NativeObjects::adopt(uint64_t handle, std::shared_ptr<KernelObject> object, bool inherit)
{
	std::lock_guard lock(mutex);
	if (handles.contains(handle))
		return false;
	handles.emplace(handle,Handle{{},0x1f0003,{},std::move(object),inherit});
	return true;
}

uint32_t NativeObjects::close(uint64_t handle)
{
	static const bool traced = std::getenv("RAVEN_TRACE_HANDLES") != nullptr;
	if (traced) std::fprintf(stderr, "handle %llx closed by %s\n", static_cast<unsigned long long>(handle), api_in_progress);
	std::shared_ptr<KernelObject> generic;
	{
		std::lock_guard lock(mutex);
		const auto found=handles.find(handle);
		if (found==handles.end()) return invalid_handle;
		generic=std::move(found->second.generic);
		handles.erase(found);
	}
	if (const auto reserved=std::dynamic_pointer_cast<ReservedObject>(generic); reserved && reserved->on_close)
		reserved->on_close(handle);
	return 0;
}

uint64_t NativeObjects::reserve(std::function<void(uint64_t)> on_close)
{
	auto object=std::make_shared<ReservedObject>();
	object->on_close=std::move(on_close);
	const auto made=add_object(object);
	return made.status ? 0 : made.value;
}

void NativeObjects::release_reserved(uint64_t handle)
{
	std::lock_guard lock(mutex);
	if (const auto found=handles.find(handle); found!=handles.end() && std::dynamic_pointer_cast<ReservedObject>(found->second.generic))
		handles.erase(found);
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

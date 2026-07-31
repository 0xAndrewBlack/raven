#include "memory.h"

#include <algorithm>
#include <array>
#include <new>
#include <stdexcept>
#include <sys/mman.h>

namespace raven {

static constexpr uint32_t invalid = 0xc000000dU, unsupported = 0xc00000bbU;
static constexpr uint32_t no_memory = 0xc0000017U, conflict = 0xc0000018U;

static int protection(uint32_t value)
{
	switch (value) {
	case 1: return PROT_NONE;
	case 2: return PROT_READ;
	case 4: return PROT_READ | PROT_WRITE;
	case 0x20: return PROT_READ | PROT_EXEC;
	case 0x40: return PROT_READ | PROT_WRITE | PROT_EXEC;
	default: return -1;
	}
}

static void put(std::span<uint8_t> bytes, size_t at, uint64_t value, size_t width = 8)
{
	for (size_t byte=0; byte<width; ++byte)
		bytes[at+byte]=uint8_t(value>>(byte*8));
}

static bool range(uint64_t address, uint64_t size)
{
	return size && size<=512*1024*1024 && address<native_user_limit && size<=native_user_limit-address;
}

NativeMemory::NativeMemory(NativeProcess &process, NativeEnvironment &environment, size_t limit)
	: process(process), environment(environment), limit(limit) {}

std::span<const std::string_view> NativeMemory::nt_exports()
{
	static constexpr std::array<std::string_view,4> names{
		"NtAllocateVirtualMemory","NtFreeVirtualMemory","NtProtectVirtualMemory","NtQueryVirtualMemory"};
	return names;
}

std::map<uint64_t,NativeMemory::Region>::iterator NativeMemory::region(uint64_t address, uint64_t size)
{
	auto found=regions.upper_bound(address);
	if (found==regions.begin())
		return regions.end();
	--found;
	return address-found->first<found->second.size && size<=found->second.size-(address-found->first) ? found : regions.end();
}

NativeMemoryRange NativeMemory::allocate(uint64_t address, uint64_t size, uint32_t type, uint32_t access)
{
	if (!range(address,size))
		return {0,0,invalid};
	if (!(type & 0x3000) || (type & ~0x3000U))
		return {0,0,unsupported};
	const auto permissions=protection(access);
	if (permissions<0)
		return {0,0,0xc0000045U};
	const bool reserve=!address || (type & 0x2000);
	const uint64_t base=address & ~(reserve ? uint64_t(65535) : uint64_t(4095));
	const uint64_t length=(size+address-base+4095) & ~uint64_t(4095);
	if (!reserve) {
		const auto found=region(base,length);
		if (found==regions.end())
			return {0,0,conflict};
		process.protect_memory(base,length,permissions);
		const auto first=(base-found->first)/4096;
		std::fill_n(found->second.pages.begin()+static_cast<ptrdiff_t>(first),length/4096,access);
		return {base,length};
	}
	if (length>limit-used || regions.size()>=10000)
		return {0,0,no_memory};
	uint64_t selected=base;
	if (!address) {
		selected=next;
		for (size_t tries=0; tries<10000; ++tries) {
			if (!range(selected,length))
				return {0,0,no_memory};
			if (process.memory_available(selected,length))
				break;
			selected+=((length+65535)&~uint64_t(65535));
			if (tries==9999)
				return {0,0,no_memory};
		}
	}
	if (!selected || !process.memory_available(selected,length))
		return {0,0,conflict};
	const bool commit=type & 0x1000;
	auto [found,inserted]=regions.emplace(selected,Region{length,access,std::vector<uint32_t>(length/4096,commit ? access : 0)});
	if (!inserted)
		return {0,0,conflict};
	try { process.map_memory(length,commit ? permissions : PROT_NONE,selected); }
	catch (...) { regions.erase(found); throw; }
	used+=length;
	if (!address)
		next=selected+((length+65535)&~uint64_t(65535));
	return {selected,length};
}

NativeMemoryRange NativeMemory::free(uint64_t address, uint64_t size, uint32_t type)
{
	if (type!=0x4000 && type!=0x8000)
		return {0,0,unsupported};
	const auto found=region(address,size);
	if (found==regions.end())
		return {0,0,conflict};
	if (type==0x8000) {
		if (size || address!=found->first)
			return {0,0,invalid};
		const auto length=found->second.size;
		process.unmap_memory(address);
		used-=length;
		regions.erase(found);
		return {address,length};
	}
	if (!size) {
		if (address!=found->first)
			return {0,0,invalid};
		size=found->second.size;
	}
	const auto base=address & ~uint64_t(4095), length=(size+address-base+4095)&~uint64_t(4095);
	if (region(base,length)==regions.end())
		return {0,0,conflict};
	process.discard_memory(base,length);
	process.protect_memory(base,length,PROT_NONE);
	const auto first=(base-found->first)/4096;
	std::fill_n(found->second.pages.begin()+static_cast<ptrdiff_t>(first),length/4096,0);
	return {base,length};
}

NativeMemoryRange NativeMemory::protect(uint64_t address, uint64_t size, uint32_t access)
{
	if (!range(address,size))
		return {0,0,invalid};
	const auto permissions=protection(access);
	if (permissions<0)
		return {0,0,0xc0000045U};
	const auto base=address & ~uint64_t(4095), length=(size+address-base+4095)&~uint64_t(4095);
	const auto found=region(base,length);
	if (found==regions.end())
		return {0,0,conflict};
	const auto first=(base-found->first)/4096, count=length/4096;
	if (std::any_of(found->second.pages.begin()+static_cast<ptrdiff_t>(first),
		found->second.pages.begin()+static_cast<ptrdiff_t>(first+count),[](auto page) { return !page; }))
		return {0,0,0xc000002dU};
	const auto previous=found->second.pages[size_t(first)];
	process.protect_memory(base,length,permissions);
	std::fill_n(found->second.pages.begin()+static_cast<ptrdiff_t>(first),count,access);
	return {base,length,0,previous};
}

std::optional<std::array<uint8_t,48>> NativeMemory::query(uint64_t address) const
{
	auto found=regions.upper_bound(address);
	if (found==regions.begin())
		return std::nullopt;
	--found;
	if (address-found->first>=found->second.size)
		return std::nullopt;
	const auto first=(address-found->first)/4096;
	const auto access=found->second.pages[size_t(first)];
	uint64_t end=first+1;
	while (end<found->second.pages.size() && found->second.pages[size_t(end)]==access)
		++end;
	std::array<uint8_t,48> bytes{};
	put(bytes,0,found->first+first*4096); put(bytes,8,found->first);
	put(bytes,16,found->second.allocation_protection,4); put(bytes,24,(end-first)*4096);
	put(bytes,32,access ? 0x1000 : 0x2000,4); put(bytes,36,access,4); put(bytes,40,0x20000,4);
	return bytes;
}

static uint32_t error(uint32_t status)
{
	if (status==unsupported) return 120;
	if (status==no_memory) return 8;
	if (status==conflict || status==0xc000002dU) return 487;
	if (status==0xc0000005U) return 998;
	return 87;
}

bool NativeMemory::dispatch(std::string_view name)
{
	const bool nt=name.starts_with("Nt");
	const bool alloc=name=="VirtualAlloc" || name=="NtAllocateVirtualMemory";
	const bool release=name=="VirtualFree" || name=="NtFreeVirtualMemory";
	const bool change=name=="VirtualProtect" || name=="NtProtectVirtualMemory";
	const bool inspect=name=="VirtualQuery" || name=="NtQueryVirtualMemory";
	if (!alloc && !release && !change && !inspect)
		return false;
	const auto args=process.api_arguments(nt ? (alloc || inspect ? 6 : change ? 5 : 4) : alloc || change ? 4 : 3);
	uint64_t result=0;
	uint32_t status=0;
	try {
		if (nt && args[0]!=UINT64_MAX)
			status=0xc0000008U;
		else if (alloc && nt && args[2])
			status=unsupported;
		else if (inspect) {
			const auto output=nt ? args[3] : args[1], size=nt ? args[4] : args[2];
			if ((nt && args[2]) || size<48)
				status=nt && args[2] ? unsupported : 0xc0000004U;
			else if (const auto info=query(args[nt ? 1 : 0])) {
				if (nt && args[5]) {
					const auto previous=process.read_memory(args[5],8);
					process.write_memory(args[5],previous);
				}
				process.write_memory(output,*info);
				if (nt && args[5]) {
					std::array<uint8_t,8> length{}; put(length,0,48); process.write_memory(args[5],length);
				}
				result=48;
			} else status=unsupported;
		} else {
			uint64_t address=args[nt ? 1 : 0], size=args[nt ? (alloc ? 3 : 2) : 1];
			const auto read=[&](uint64_t pointer) {
				const auto bytes=process.read_memory(pointer,8); process.write_memory(pointer,bytes);
				uint64_t value=0; for (size_t byte=0; byte<8; ++byte) value|=uint64_t(bytes[byte])<<(byte*8);
				return value;
			};
			if (nt) { address=read(address); size=read(size); }
			const auto old=change ? args[nt ? 4 : 3] : 0;
			if (change) {
				const auto bytes=process.read_memory(old,4); process.write_memory(old,bytes);
			}
			const auto base=address & ~uint64_t(4095);
			uint64_t length=(size+address-base+4095)&~uint64_t(4095);
			if (release && !size)
				if (const auto info=query(address)) {
					length=0; for (size_t byte=0; byte<8; ++byte) length|=uint64_t((*info)[24+byte])<<(byte*8);
				}
			const auto overlaps=[&](uint64_t pointer, size_t width) { return pointer<base+length && pointer+width>base; };
			if ((change && overlaps(old,4)) || (nt && (overlaps(args[1],8) || overlaps(args[alloc ? 3 : 2],8))))
				status=unsupported;
			else {
				const auto operation=alloc ? allocate(address,size,uint32_t(args[nt ? 4 : 2]),uint32_t(args[nt ? 5 : 3])) :
					release ? free(address,size,uint32_t(args[nt ? 3 : 2])) : protect(address,size,uint32_t(args[nt ? 3 : 2]));
				status=operation.status;
				if (!status) {
					if (nt) {
						std::array<uint8_t,8> output{}; put(output,0,operation.address); process.write_memory(args[1],output);
						put(output,0,operation.size); process.write_memory(args[alloc ? 3 : 2],output);
					}
					if (change) { std::array<uint8_t,4> output{}; put(output,0,operation.previous,4); process.write_memory(old,output); }
					result=alloc ? operation.address : 1;
				}
			}
		}
	} catch (const std::bad_alloc &) {
		status=no_memory;
	} catch (const std::runtime_error &failure) {
		const std::string_view message=failure.what();
		if (message.find("readable")==message.npos && message.find("writable")==message.npos)
			throw;
		status=0xc0000005U;
	}
	if (!nt && status)
		environment.set_last_error(status==0xc0000004U ? 24 : error(status));
	process.return_api(nt ? status : status ? 0 : result);
	return true;
}

}

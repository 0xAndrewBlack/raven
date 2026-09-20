#define WIN32_LEAN_AND_MEAN
#include <windows.h>

LONG NTAPI NtAllocateVirtualMemory(HANDLE,void **,ULONG_PTR,SIZE_T *,ULONG,ULONG);
LONG NTAPI NtFreeVirtualMemory(HANDLE,void **,SIZE_T *,ULONG);
LONG NTAPI NtProtectVirtualMemory(HANDLE,void **,SIZE_T *,ULONG,ULONG *);
LONG NTAPI NtQueryVirtualMemory(HANDLE,void *,ULONG,void *,SIZE_T,SIZE_T *);

__declspec(dllexport) volatile unsigned phase;

int raven_entry(void)
{
	BYTE *base=VirtualAlloc(NULL,8192,MEM_RESERVE,PAGE_READWRITE);
	MEMORY_BASIC_INFORMATION info;
	if (!base || (ULONG_PTR)base%65536 || VirtualQuery(base,&info,sizeof(info))!=sizeof(info) ||
		info.BaseAddress!=base || info.AllocationBase!=base || info.RegionSize!=8192 ||
		info.State!=MEM_RESERVE || info.Protect || info.AllocationProtect!=PAGE_READWRITE || info.Type!=MEM_PRIVATE)
		return 1;
	DWORD old=0x11223344;
	if (VirtualProtect(base,4096,PAGE_READWRITE,&old) || old!=0x11223344)
		return 2;
	phase=1;
	void *part=base+4101;
	SIZE_T size=1;
	SetLastError(77);
	if (NtAllocateVirtualMemory((HANDLE)-1,&part,0,&size,MEM_COMMIT,PAGE_READWRITE)!=0 ||
		part!=base+4096 || size!=4096 || GetLastError()!=77)
		return 3;
	for (unsigned byte=0; byte<4096; ++byte) {
		if (((BYTE *)part)[byte]) return 4;
		((BYTE *)part)[byte]=0xa5;
	}
	SIZE_T length=0;
	if (NtQueryVirtualMemory((HANDLE)-1,part,0,&info,sizeof(info),&length)!=0 || length!=sizeof(info) ||
		info.BaseAddress!=part || info.AllocationBase!=base || info.RegionSize!=4096 || info.State!=MEM_COMMIT || info.Protect!=PAGE_READWRITE)
		return 5;
	if (!VirtualProtect(part,4096,PAGE_READONLY,&old) || old!=PAGE_READWRITE ||
		VirtualQuery(part,&info,sizeof(info))!=sizeof(info) || info.Protect!=PAGE_READONLY)
		return 6;
	size=1;
	if (NtProtectVirtualMemory((HANDLE)-1,&part,&size,PAGE_READWRITE,&old)!=0 || old!=PAGE_READONLY || size!=4096)
		return 7;
	phase=2;
	size=4096;
	if (NtAllocateVirtualMemory((HANDLE)-1,&part,0,&size,MEM_COMMIT,PAGE_READWRITE)!=0)
		return 8;
	for (unsigned byte=0; byte<4096; ++byte)
		if (((BYTE *)part)[byte]!=0xa5) return 9;
	void *decommit=(BYTE *)part+7;
	size=1;
	if (NtFreeVirtualMemory((HANDLE)-1,&decommit,&size,MEM_DECOMMIT)!=0 || decommit!=part || size!=4096 ||
		VirtualQuery(part,&info,sizeof(info))!=sizeof(info) || info.State!=MEM_RESERVE || info.Protect)
		return 10;
	size=4096;
	if (NtAllocateVirtualMemory((HANDLE)-1,&part,0,&size,MEM_COMMIT,PAGE_READWRITE)!=0)
		return 11;
	for (unsigned byte=0; byte<4096; ++byte)
		if (((BYTE *)part)[byte]) return 12;
	void *release=base;
	size=0;
	if (NtFreeVirtualMemory((HANDLE)-1,&release,&size,MEM_RELEASE)!=0 || release!=base || size!=8192)
		return 13;
	BYTE *implicit=VirtualAlloc(NULL,1,MEM_COMMIT,PAGE_READWRITE);
	if (!implicit || *implicit || !VirtualFree(implicit,0,MEM_RELEASE))
		return 14;
	phase=3;
	/* Single pages committed one after another in a large reservation, then decommitted and committed again: the later ones may be
	 * done without the runtime seeing the call, and the state they leave must still be what Windows reports. */
	BYTE *pool=VirtualAlloc(NULL,1<<20,MEM_RESERVE,PAGE_READWRITE);
	if (!pool || VirtualAlloc(pool+0x3000,4096,MEM_COMMIT,PAGE_READWRITE)!=pool+0x3000)
		return 15;
	pool[0x3000]=1;
	if (VirtualAlloc(pool+0x5100,100,MEM_COMMIT,PAGE_READWRITE)!=pool+0x5000 || pool[0x5000] || pool[0x5fff])
		return 16;
	pool[0x5000]=2;
	if (VirtualQuery(pool+0x5000,&info,sizeof(info))!=sizeof(info) || info.State!=MEM_COMMIT || info.Protect!=PAGE_READWRITE ||
		info.RegionSize!=4096 || VirtualQuery(pool+0x4000,&info,sizeof(info))!=sizeof(info) || info.State!=MEM_RESERVE || info.Protect)
		return 17;
	if (!VirtualFree(pool+0x5000,4096,MEM_DECOMMIT) || VirtualQuery(pool+0x5000,&info,sizeof(info))!=sizeof(info) ||
		info.State!=MEM_RESERVE || pool[0x3000]!=1)
		return 18;
	if (VirtualAlloc(pool+0x5000,4096,MEM_COMMIT,PAGE_READWRITE)!=pool+0x5000 || pool[0x5000] ||
		VirtualQuery(pool+0x5000,&info,sizeof(info))!=sizeof(info) || info.State!=MEM_COMMIT)
		return 19;
	/* The same through NtAllocateVirtualMemory, which rounds the base and size it is given and writes them back. */
	void *native=pool+0x7123;
	size=0x1000;
	if (NtAllocateVirtualMemory((HANDLE)-1,&native,0,&size,MEM_COMMIT,PAGE_READWRITE)!=0 || native!=pool+0x7000 || size!=0x2000 ||
		pool[0x7000] || pool[0x8fff])
		return 21;
	pool[0x8fff]=3;
	if (VirtualQuery(pool+0x7000,&info,sizeof(info))!=sizeof(info) || info.State!=MEM_COMMIT || info.Protect!=PAGE_READWRITE ||
		info.RegionSize!=0x2000 || VirtualQuery(pool+0x9000,&info,sizeof(info))!=sizeof(info) || info.State!=MEM_RESERVE)
		return 22;
	void *gone=pool+0x7800;
	size=0x900;
	if (NtFreeVirtualMemory((HANDLE)-1,&gone,&size,MEM_DECOMMIT)!=0 || gone!=pool+0x7000 || size!=0x2000 ||
		VirtualQuery(pool+0x7000,&info,sizeof(info))!=sizeof(info) || info.State!=MEM_RESERVE || info.RegionSize<0x2000)
		return 23;
	size=0x1000;
	native=pool+0x8000;
	if (NtAllocateVirtualMemory((HANDLE)-1,&native,0,&size,MEM_COMMIT,PAGE_READWRITE)!=0 || pool[0x8fff])
		return 24;
	if (!VirtualFree(pool,0,MEM_RELEASE))
		return 20;
	phase=4;
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

typedef void *(NTAPI *CREATE_HEAP)(ULONG,void *,SIZE_T,SIZE_T,void *,void *);
__declspec(dllexport) volatile unsigned phase;
static HANDLE heaps[512];

int raven_entry(void)
{
	BYTE *peb=(BYTE *)__readgsqword(0x60);
	DWORD *count=(DWORD *)(peb+0xe8), *capacity=(DWORD *)(peb+0xec);
	HANDLE *list=*(HANDLE **)(peb+0xf0);
	HANDLE process=GetProcessHeap();
	if (!process || *count!=1 || *capacity!=512 || list[0]!=process) return 1;
	CREATE_HEAP create=(CREATE_HEAP)GetProcAddress(GetModuleHandleW(L"raven-rtl.dll"),"RtlCreateHeap");
	if (!create) return 2;
	for (unsigned i=0;i<511;++i) {
		heaps[i]=(i & 1) ? HeapCreate(0,4096,0) : create(2,NULL,65536,4096,NULL,NULL);
		if (!heaps[i] || *count!=i+2 || list[i+1]!=heaps[i]) return 3;
	}
	SetLastError(71);
	if (HeapCreate(0,4096,0) || *count!=512 || GetLastError()!=ERROR_NOT_ENOUGH_MEMORY) return 4;
	if (create(2,NULL,65536,4096,NULL,NULL) || *count!=512) return 5;
	phase=1;
	for (unsigned i=511;i>0;--i) {
		if (!HeapDestroy(heaps[i-1]) || *count!=i || list[i]) return 6;
	}
	if (HeapDestroy(process) || *count!=1 || GetProcessHeap()!=process || list[0]!=process) return 7;
	BYTE *bytes=HeapAlloc(process,HEAP_ZERO_MEMORY,97);
	if (!bytes) return 8;
	for (unsigned i=0;i<97;++i) if (bytes[i]) return 9;
	if (!HeapFree(process,0,bytes)) return 10;
	SetLastError(71);
	if (HeapAlloc(process,0x80000000,32) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 11;
	phase=2;
	return 0;
}

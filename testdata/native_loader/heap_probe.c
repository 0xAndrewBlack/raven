#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static unsigned attached;
static SIZE_T initial_commit, remaining_commit;
__declspec(dllexport) unsigned heap_attached(void) { return attached; }
__declspec(dllexport) SIZE_T heap_initial_commit(void) { return initial_commit; }
__declspec(dllexport) SIZE_T heap_remaining_commit(void) { return remaining_commit; }

BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved)
{
	(void)instance; (void)reserved;
	if (reason==DLL_PROCESS_ATTACH) {
		HANDLE heap=GetProcessHeap();
		MEMORY_BASIC_INFORMATION information;
		if (VirtualQuery(heap,&information,sizeof(information))!=sizeof(information) || information.State!=MEM_COMMIT)
			return FALSE;
		initial_commit=information.RegionSize;
		BYTE *bytes=HeapAlloc(heap,HEAP_ZERO_MEMORY,32);
		if (!heap || !bytes) return FALSE;
		for (unsigned i=0;i<32;++i) if (bytes[i]) return FALSE;
		bytes[31]=0x5a;
		if (!HeapFree(heap,0,bytes)) return FALSE;
		if (VirtualQuery(heap,&information,sizeof(information))!=sizeof(information) || information.State!=MEM_COMMIT)
			return FALSE;
		remaining_commit=information.RegionSize;
		attached=1;
	}
	return TRUE;
}

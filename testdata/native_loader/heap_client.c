#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <intrin.h>

void *NTAPI RtlCreateHeap(ULONG,void *,SIZE_T,SIZE_T,void *,void *);
void *NTAPI RtlAllocateHeap(void *,ULONG,SIZE_T);
void *NTAPI RtlReAllocateHeap(void *,ULONG,void *,SIZE_T);
SIZE_T NTAPI RtlSizeHeap(void *,ULONG,void *);
BOOLEAN NTAPI RtlFreeHeap(void *,ULONG,void *);
void *NTAPI RtlDestroyHeap(void *);
__declspec(dllimport) unsigned heap_attached(void);
__declspec(dllimport) SIZE_T heap_initial_commit(void);
__declspec(dllexport) volatile unsigned phase;

int raven_entry(void)
{
	HANDLE process=GetProcessHeap();
	if (!process || heap_attached()!=1 || *(void **)(__readgsqword(0x60)+0x30)!=process) return 1;
	MEMORY_BASIC_INFORMATION information;
	if (VirtualQuery(process,&information,sizeof(information))!=sizeof(information) ||
		information.AllocationBase!=process || information.State!=MEM_COMMIT || !information.RegionSize || heap_initial_commit()<8192) return 16;
	SetLastError(71);
	BYTE *bytes=HeapAlloc(process,HEAP_ZERO_MEMORY,37);
	if (!bytes || GetLastError()!=71) return 2;
	for (unsigned i=0;i<37;++i) { if (bytes[i]) return 3; bytes[i]=(BYTE)i; }
	BYTE *grown=RtlReAllocateHeap(process,HEAP_ZERO_MEMORY,bytes,9000);
	if (!grown || RtlSizeHeap(process,0,grown)!=HeapSize(process,0,grown)) return 4;
	for (unsigned i=0;i<9000;++i) if (grown[i]!=(i<37 ? (BYTE)i : 0)) return 5;
	if (!HeapFree(process,0,grown)) return 6;
	phase=1;
	HANDLE private=HeapCreate(0,4096,0);
	if (!private || private==process) return 7;
	bytes=RtlAllocateHeap(private,HEAP_ZERO_MEMORY,97);
	if (!bytes) return 8;
	for (unsigned i=0;i<97;++i) { if (bytes[i]) return 9; bytes[i]=0x5a; }
	grown=HeapReAlloc(private,HEAP_ZERO_MEMORY,bytes,17000);
	if (!grown || HeapSize(private,0,grown)<17000) return 10;
	for (unsigned i=0;i<17000;++i) if (grown[i]!=(i<97 ? 0x5a : 0)) return 11;
	if (!RtlFreeHeap(private,0,grown) || !HeapDestroy(private)) return 12;
	phase=2;
	private=RtlCreateHeap(2,NULL,65536,4096,NULL,NULL);
	bytes=HeapAlloc(private,HEAP_ZERO_MEMORY,4113);
	if (!private || !bytes || RtlSizeHeap(private,0,bytes)<4113) return 13;
	for (unsigned i=0;i<4113;++i) if (bytes[i]) return 14;
	if (!HeapFree(private,0,bytes) || RtlDestroyHeap(private)) return 15;
	phase=3;
	return 0;
}

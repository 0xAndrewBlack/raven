#define WIN32_LEAN_AND_MEAN
#include <windows.h>

LONG NTAPI NtQuerySystemInformation(ULONG,void *,ULONG,ULONG *);

typedef struct {
	ULONG reserved,timer,page,pages,lowest,highest,granularity;
	ULONG_PTR minimum,maximum,affinity;
	BYTE processors;
} BasicInformation;

__declspec(dllexport) volatile unsigned phase;

int raven_entry(void)
{
	BasicInformation info;
	ULONG length=0;
	SetLastError(71);
	if (sizeof(info)!=64 || NtQuerySystemInformation(0,&info,sizeof(info),&length)!=0 || length!=sizeof(info) ||
		GetLastError()!=71 || info.reserved || info.page!=4096 || info.granularity!=65536 ||
		!info.pages || info.highest<info.lowest || info.minimum!=65536 ||
		info.maximum<=info.minimum || !info.affinity || !info.processors)
		return 1;
	length=0;
	if ((ULONG)NtQuerySystemInformation(0,&info,sizeof(info)-1,&length)!=0xc0000004UL || length!=sizeof(info))
		return 2;
	if (NtQuerySystemInformation(0,&info,sizeof(info),NULL)!=0)
		return 3;
	phase=1;
	return 0;
}

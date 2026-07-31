#define WIN32_LEAN_AND_MEAN
#include <windows.h>

LONG NTAPI NtCreateEvent(HANDLE *,ULONG,void *,ULONG,BOOLEAN);
LONG NTAPI NtClose(HANDLE);
LONG NTAPI NtSetEvent(HANDLE,LONG *);
LONG NTAPI NtResetEvent(HANDLE,LONG *);
LONG NTAPI NtQueryEvent(HANDLE,ULONG,void *,ULONG,ULONG *);
LONG NTAPI NtWaitForSingleObject(HANDLE,BOOLEAN,LARGE_INTEGER *);

__declspec(dllexport) volatile unsigned phase;

int raven_entry(void)
{
	HANDLE manual=NULL;
	SetLastError(71);
	if (NtCreateEvent(&manual,0x1f0003,NULL,0,FALSE)!=0 || !manual || GetLastError()!=71)
		return 1;
	LONG state[2]={-1,-1};
	ULONG length=0;
	LARGE_INTEGER poll; poll.QuadPart=0;
	if (NtQueryEvent(manual,0,state,sizeof(state),&length)!=0 || length!=sizeof(state) || state[0] || state[1] ||
		(ULONG)NtWaitForSingleObject(manual,FALSE,&poll)!=0x102)
		return 2;
	LONG previous=-1;
	if (NtSetEvent(manual,&previous)!=0 || previous || NtWaitForSingleObject(manual,FALSE,&poll)!=0 ||
		WaitForSingleObject(manual,0)!=WAIT_OBJECT_0 || !ResetEvent(manual) || WaitForSingleObject(manual,0)!=WAIT_TIMEOUT)
		return 3;
	phase=1;
	HANDLE automatic=CreateEventW(NULL,FALSE,TRUE,NULL);
	if (!automatic || WaitForSingleObject(automatic,0)!=WAIT_OBJECT_0 || WaitForSingleObject(automatic,0)!=WAIT_TIMEOUT ||
		!SetEvent(automatic) || NtWaitForSingleObject(automatic,FALSE,&poll)!=0 ||
		NtQueryEvent(automatic,0,state,sizeof(state),NULL)!=0 || state[0]!=1 || state[1])
		return 4;
	previous=-1;
	if (NtResetEvent(manual,&previous)!=0 || previous || !CloseHandle(manual) || NtClose(automatic)!=0)
		return 5;
	if ((ULONG)NtClose(automatic)!=0xc0000008UL || (ULONG)NtSetEvent(manual,NULL)!=0xc0000008UL)
		return 6;
	phase=2;
	return 0;
}

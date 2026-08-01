#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG counter;
static CRITICAL_SECTION guard;
static HANDLE signal_event, release_event;
static volatile DWORD seen_ids[3];

static DWORD WINAPI count_up(LPVOID parameter)
{
	DWORD index=(DWORD)(DWORD_PTR)parameter;
	seen_ids[index]=GetCurrentThreadId();
	for (int step=0; step<100; ++step) {
		EnterCriticalSection(&guard);
		LONG seen=counter;
		if (step%10==0) Sleep(0);
		counter=seen+1;
		LeaveCriticalSection(&guard);
	}
	return 40+index;
}

static DWORD WINAPI notify(LPVOID parameter)
{
	(void)parameter;
	if (WaitForSingleObject(release_event,5000)!=WAIT_OBJECT_0) return 1;
	SetEvent(signal_event);
	ExitThread(77);
	return 2;
}

int raven_entry(void)
{
	HANDLE workers[2];
	DWORD id=0,code=0;
	InitializeCriticalSection(&guard);
	for (DWORD index=0; index<2; ++index) {
		workers[index]=CreateThread(0,0,count_up,(LPVOID)(DWORD_PTR)(index+1),0,&id);
		if (!workers[index] || !id) return 1;
	}
	for (DWORD index=0; index<2; ++index) {
		if (WaitForSingleObject(workers[index],5000)!=WAIT_OBJECT_0) return 2;
		if (!GetExitCodeThread(workers[index],&code) || code!=41+index) return 3;
		CloseHandle(workers[index]);
	}
	if (counter!=200) return 4;
	if (!seen_ids[1] || !seen_ids[2] || seen_ids[1]==seen_ids[2] || seen_ids[1]==GetCurrentThreadId()) return 5;
	signal_event=CreateEventA(0,FALSE,FALSE,0);
	release_event=CreateEventA(0,FALSE,FALSE,0);
	HANDLE waiter=CreateThread(0,0,notify,0,0,&id);
	if (!waiter) return 6;
	if (WaitForSingleObject(signal_event,50)!=WAIT_TIMEOUT) return 7;
	SetEvent(release_event);
	if (WaitForSingleObject(signal_event,5000)!=WAIT_OBJECT_0) return 8;
	if (WaitForSingleObject(waiter,5000)!=WAIT_OBJECT_0) return 9;
	if (!GetExitCodeThread(waiter,&code) || code!=77) return 10;
	return 0;
}

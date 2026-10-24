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

static int critical_options(void)
{
	ULONG_PTR peb;
#ifdef __x86_64__
	__asm__ volatile("movq %%gs:0x60,%0" : "=r"(peb));
	const BYTE *version = (const BYTE *)(peb + 0x118);
#else
	__asm__ volatile("movl %%fs:0x30,%0" : "=r"(peb));
	const BYTE *version = (const BYTE *)(peb + 0xa4);
#endif
	if (*(const DWORD *)version != 10 || *(const DWORD *)(version + 4) ||
		*(const WORD *)(version + 8) != 19045 || *(const WORD *)(version + 10) ||
		*(const DWORD *)(version + 12) != VER_PLATFORM_WIN32_NT) return 85;
	CRITICAL_SECTION option;
	const DWORD flags[] = {1, 0x00ffffff, 0x01000001, 0x10000000};
	for (unsigned index = 0; index < sizeof(flags) / sizeof(flags[0]); ++index) {
		for (unsigned at = 0; at < sizeof(option); ++at) ((BYTE *)&option)[at] = 0xa5;
		if (!InitializeCriticalSectionEx(&option, 0, flags[index])) return 80;
		if ((flags[index] & 0x01000000) && option.DebugInfo && (ULONG_PTR)option.DebugInfo != (ULONG_PTR)-1) return 81;
		EnterCriticalSection(&option);
		if (!TryEnterCriticalSection(&option)) return 82;
		LeaveCriticalSection(&option);
		LeaveCriticalSection(&option);
		DeleteCriticalSection(&option);
	}
	for (unsigned at = 0; at < sizeof(option); ++at) ((BYTE *)&option)[at] = 0xa5;
	if (InitializeCriticalSectionEx(&option, 0, 0x20000001) || GetLastError() != ERROR_INVALID_PARAMETER) return 83;
	for (unsigned at = 0; at < sizeof(option); ++at) if (((BYTE *)&option)[at] != 0xa5) return 84;
	return 0;
}

int raven_entry(void)
{
	const int options = critical_options();
	if (options) return options;
	HANDLE workers[2];
	DWORD id=0,code=0;
	if (!InitializeCriticalSectionEx(&guard,0,1)) return 79;
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

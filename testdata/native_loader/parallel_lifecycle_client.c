#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG counter;
static WCHAR mode;

static DWORD WINAPI worker(void *parameter)
{
	(void)parameter;
	if (mode == 'f') {
		Sleep(20);
		*(volatile LONG *)(ULONG_PTR)0x123 = 42;
	}
	for (;;) InterlockedIncrement(&counter);
}

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW(), *argument = line;
	for (const WCHAR *at = line; *at; ++at)
		if (*at == ' ') argument = at + 1;
	mode = *argument;
	if (!CreateThread(0, 0, worker, 0, 0, 0)) return 1;
	if (mode == 'f' || mode == 't')
		for (;;) InterlockedIncrement(&counter);
	Sleep(20);
	return 0;
}

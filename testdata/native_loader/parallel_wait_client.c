#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG completed;
static DWORD caller;

static void CALLBACK elapsed(void *context, BOOLEAN timed_out)
{
	const LONG result = context == &completed && timed_out && GetCurrentThreadId() != caller ? 1 : 2;
	InterlockedExchange(&completed, result);
}

int raven_entry(void)
{
	caller = GetCurrentThreadId();
	HANDLE event = CreateEventW(NULL, TRUE, FALSE, NULL), wait = NULL;
	if (!event || !RegisterWaitForSingleObject(&wait, event, elapsed, (void *)&completed, 30, WT_EXECUTEONLYONCE))
		return 1;
	SetLastError(317);
	/* The wait expires while the only guest thread runs without entering an API. */
	while (!InterlockedCompareExchange(&completed, 0, 0)) {}
	if (completed != 1 || GetLastError() != 317 || GetCurrentThreadId() != caller)
		return 2;
	if (!UnregisterWaitEx(wait, INVALID_HANDLE_VALUE))
		return 3;
	CloseHandle(event);
	return 0;
}

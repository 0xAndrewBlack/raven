#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG ready;
static HANDLE start;

static DWORD WINAPI calls(void *parameter)
{
	const DWORD identity = GetCurrentThreadId();
	const DWORD marker = 1234 + (DWORD)(ULONG_PTR)parameter;
	LARGE_INTEGER frequency, previous;
	if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0 || !QueryPerformanceCounter(&previous))
		return 10;
	InterlockedIncrement(&ready);
	if (WaitForSingleObject(start, 5000) != WAIT_OBJECT_0)
		return 11;
	SetLastError(marker);
	for (unsigned i = 0; i < 2000; ++i) {
		struct {
			ULONGLONG before;
			LARGE_INTEGER value;
			ULONGLONG after;
		} counter = {marker, {.QuadPart = -1}, marker}, rate = {marker, {.QuadPart = -1}, marker};
		if (!QueryPerformanceCounter(&counter.value) || !QueryPerformanceFrequency(&rate.value))
			return 12;
		if (counter.value.QuadPart < previous.QuadPart || rate.value.QuadPart != frequency.QuadPart)
			return 13;
		if (counter.before != marker || counter.after != marker || rate.before != marker || rate.after != marker)
			return 14;
		if (GetLastError() != marker || GetCurrentThreadId() != identity)
			return 15;
		previous = counter.value;
	}
	return 0;
}

int raven_entry(void)
{
	start = CreateEventW(NULL, TRUE, FALSE, NULL);
	if (!start)
		return 1;
	HANDLE threads[4];
	for (unsigned i = 0; i < 4; ++i) {
		threads[i] = CreateThread(NULL, 0, calls, (void *)(ULONG_PTR)i, 0, NULL);
		if (!threads[i])
			return 2;
	}
	for (unsigned i = 0; ready != 4 && i < 5000; ++i)
		Sleep(1);
	if (ready != 4 || !SetEvent(start))
		return 3;
	for (unsigned i = 0; i < 4; ++i) {
		DWORD code;
		if (WaitForSingleObject(threads[i], 10000) != WAIT_OBJECT_0 || !GetExitCodeThread(threads[i], &code))
			return 4;
		if (code)
			return code;
		CloseHandle(threads[i]);
	}
	CloseHandle(start);
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* The millisecond clocks are the performance counter in milliseconds, whether the runtime or the program reads them. */

static LONGLONG distance(ULONGLONG left, ULONGLONG right)
{
	return left > right ? (LONGLONG)(left - right) : (LONGLONG)(right - left);
}

int raven_entry(void)
{
	/* Long enough for the runtime to have calibrated the time stamp counter against the performance counter. */
	Sleep(400);
	LARGE_INTEGER frequency, counter;
	if (!QueryPerformanceFrequency(&frequency) || frequency.QuadPart != 10000000 || !QueryPerformanceCounter(&counter))
		return 1;
	const ULONGLONG ticks = GetTickCount64();
	if (distance(ticks, (ULONGLONG)counter.QuadPart / 10000) > 5)
		return 2;
	if (distance(GetTickCount(), (DWORD)GetTickCount64()) > 5)
		return 3;
	Sleep(50);
	const ULONGLONG later = GetTickCount64();
	if (later < ticks + 45 || later > ticks + 250)
		return 4;
	return 0;
}

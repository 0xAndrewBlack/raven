#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG counter[2];

static DWORD WINAPI worker(void *parameter)
{
	unsigned index = (unsigned)(ULONG_PTR)parameter;
	for (;;) {
		InterlockedIncrement(&counter[index]);
		if (index)
			Sleep(0);
	}
}

int raven_entry(void)
{
	HANDLE threads[2];
	for (unsigned i = 0; i < 2; ++i) {
		threads[i] = CreateThread(0, 0, worker, (void *)(ULONG_PTR)i, 0, 0);
		if (!threads[i]) return 1;
	}
	for (unsigned round = 0; round < 50; ++round) {
		for (unsigned i = 0; i < 2; ++i) {
			LONG before = counter[i];
			for (unsigned delay = 0; counter[i] == before && delay < 1000; ++delay)
				Sleep(1);
			if (counter[i] == before) return 2;
			if (SuspendThread(threads[i]) != 0) return 3;
			before = counter[i];
#ifdef __x86_64__
			CONTEXT context;
			context.ContextFlags = CONTEXT_CONTROL;
			if (!GetThreadContext(threads[i], &context) || !context.Rip || !context.Rsp) return 4;
#endif
			if (SuspendThread(threads[i]) != 1) return 5;
			Sleep(2);
			if (counter[i] != before) return 6;
			if (ResumeThread(threads[i]) != 2) return 7;
			Sleep(2);
			if (counter[i] != before) return 8;
			if (ResumeThread(threads[i]) != 1) return 9;
		}
	}
	for (unsigned i = 0; i < 2; ++i) {
		DWORD code;
		if (!TerminateThread(threads[i], 77)) return 10;
		LONG before = counter[i];
		Sleep(5);
		if (counter[i] != before) return 11;
		if (WaitForSingleObject(threads[i], 1000) != WAIT_OBJECT_0) return 12;
		if (!GetExitCodeThread(threads[i], &code) || code != 77) return 13;
		if (SuspendThread(threads[i]) != (DWORD)-1) return 14;
		CloseHandle(threads[i]);
	}
	return 0;
}

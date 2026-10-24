#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG ready, stop;
static volatile ULONGLONG values[2];
static DWORD identities[2];
static DWORD slot;

static DWORD WINAPI compute(void *parameter)
{
	unsigned index = (unsigned)(ULONG_PTR)parameter;
	identities[index] = GetCurrentThreadId();
	TlsSetValue(slot, (void *)(ULONG_PTR)(123 + index));
	SetLastError(321 + index);
	InterlockedIncrement(&ready);
	ULONGLONG value = 123 + index;
	while (!stop) {
		for (unsigned i = 0; i < 1024; ++i)
			value = value * 6364136223846793005ULL + 1;
		values[index] = value;
	}
	if (GetLastError() != 321 + index)
		return 13;
	if (TlsGetValue(slot) != (void *)(ULONG_PTR)(123 + index))
		return 11;
	return GetCurrentThreadId() == identities[index] ? 0 : 12;
}

int raven_entry(void)
{
	slot = TlsAlloc();
	if (slot == TLS_OUT_OF_INDEXES)
		return 1;
	HANDLE threads[2];
	for (unsigned i = 0; i < 2; ++i) {
		threads[i] = CreateThread(NULL, 0, compute, (void *)(ULONG_PTR)i, 0, NULL);
		if (!threads[i])
			return 2;
	}
	for (unsigned i = 0; ready != 2 && i < 5000; ++i)
		Sleep(1);
	if (ready != 2)
		return 3;
	Sleep(2000);
	InterlockedExchange(&stop, 1);
	for (unsigned i = 0; i < 2; ++i) {
		DWORD code;
		if (WaitForSingleObject(threads[i], 5000) != WAIT_OBJECT_0 || !GetExitCodeThread(threads[i], &code) || code)
			return 4;
		CloseHandle(threads[i]);
	}
	TlsFree(slot);
	return values[0] && values[1] && identities[0] != identities[1] ? 0 : 5;
}

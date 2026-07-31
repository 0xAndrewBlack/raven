#include <windows.h>
#include <delayimp.h>
#include <stdint.h>

__declspec(dllimport) DWORD Named(void);
__declspec(dllimport) DWORD Ordinal(DWORD value);
__declspec(dllexport) volatile DWORD entered;
__declspec(dllexport) volatile DWORD failure_error;
__declspec(dllexport) volatile DWORD failure_reason;
__declspec(dllexport) DWORD loads, procedures, starts, ends;

static FARPROC WINAPI notify(unsigned reason, PDelayLoadInfo info)
{
	(void)info;
	if (reason == dliStartProcessing)
		++starts;
	else if (reason == dliNotePreLoadLibrary)
		++loads;
	else if (reason == dliNotePreGetProcAddress)
		++procedures;
	else if (reason == dliNoteEndProcessing)
		++ends;
	return 0;
}

static FARPROC WINAPI failure(unsigned reason, PDelayLoadInfo info)
{
	failure_error = info->dwLastError;
	failure_reason = reason;
	return 0;
}

PfnDliHook __pfnDliNotifyHook2 = notify;
PfnDliHook __pfnDliFailureHook2 = failure;

// Reload the IAT at each call; GCC otherwise keeps the original delay thunk in a register.
__attribute__((noinline)) static DWORD invoke_named(void)
{
	return Named();
}

__attribute__((noinline)) static DWORD invoke_ordinal(DWORD value)
{
	return Ordinal(value);
}

DWORD raven_entry(void)
{
	if (GetModuleHandleA("delayed.dll") || loads || procedures)
		return 1;
	if (invoke_named() != 19)
		return 2;
	entered = 1;
	HMODULE module = GetModuleHandleA("delayed.dll");
	if (!module || invoke_ordinal(91) != 19 || invoke_named() != 91 || invoke_ordinal(25) != 91)
		return 3;
	if (loads != 1 || procedures != 2 || starts != 2 || ends != 2 || failure_error)
		return 4;
	if (!FreeLibrary(module) || GetModuleHandleA("delayed.dll"))
		return 5;
	return 0;
}

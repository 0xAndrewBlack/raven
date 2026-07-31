#include <windows.h>
#include <winternl.h>

extern unsigned char __ImageBase;

unsigned int raven_entry(void)
{
	PTEB teb = NtCurrentTeb();
	if (!teb || *(void **)((char *)teb + 0x30) != teb || !teb->ProcessEnvironmentBlock)
		return 1;
	if ((ULONG_PTR)&teb <= *(ULONG_PTR *)((char *)teb + 0x10) ||
		(ULONG_PTR)&teb >= *(ULONG_PTR *)((char *)teb + 0x08))
		return 7;
	if (*(void **)((char *)teb->ProcessEnvironmentBlock + 0x10) != &__ImageBase)
		return 2;
	if (GetCurrentProcessId() != (DWORD)*(ULONG_PTR *)((char *)teb + 0x40) ||
		GetCurrentThreadId() != (DWORD)*(ULONG_PTR *)((char *)teb + 0x48))
		return 3;
	SetLastError(0x81234567);
	if (GetLastError() != 0x81234567 || *(DWORD *)((char *)teb + 0x68) != 0x81234567)
		return 4;
	*(DWORD *)((char *)teb + 0x68) = 42;
	if (GetLastError() != 42 || GetLastError() != 42)
		return 5;
	SetLastError(0);
	if (GetLastError() != 0)
		return 6;
	return 0;
}

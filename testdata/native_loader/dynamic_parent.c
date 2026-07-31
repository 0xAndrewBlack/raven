#include <windows.h>

__declspec(dllimport) DWORD QueryTLS(void);

__declspec(dllexport) DWORD QueryDependency(void)
{
	return QueryTLS();
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
	(void)module;
#ifdef RAVEN_DYNAMIC_DETACH_FAULT
	if (reason == DLL_PROCESS_DETACH && !reserved)
		*(volatile DWORD *)0 = 7;
#endif
#ifdef RAVEN_DYNAMIC_DETACH_LOOP
	if (reason == DLL_PROCESS_DETACH && !reserved)
		for (;;) __asm__ volatile("pause");
#endif
	if (reason == DLL_PROCESS_ATTACH) {
		if (reserved || !QueryTLS())
			return FALSE;
#ifdef RAVEN_DYNAMIC_FAULT
		*(volatile DWORD *)0 = 7;
#endif
#ifdef RAVEN_DYNAMIC_LOOP
		for (;;) __asm__ volatile("pause");
#endif
#ifdef RAVEN_DYNAMIC_REJECT
		return FALSE;
#endif
	}
	return TRUE;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllexport) DWORD sequence;

int raven_entry(void)
{
	HMODULE module=LoadLibraryW(L"tls-order.dll");
	if (!module) return 1;
	BOOL (*observe)(DWORD *,BOOL)=(BOOL (*)(DWORD *,BOOL))GetProcAddress(module,"ObserveDetach");
	if (!observe || !observe(&sequence,
#ifdef RAVEN_TLS_ORDER_SHUTDOWN
		TRUE
#else
		FALSE
#endif
		) || sequence!=12) return 2;
#ifndef RAVEN_TLS_ORDER_SHUTDOWN
	if (!FreeLibrary(module) || sequence!=1234) return 3;
#endif
	return 0;
}

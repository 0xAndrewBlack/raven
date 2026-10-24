#include <windows.h>
#include <winternl.h>

__declspec(dllexport) unsigned int base_state;
__declspec(dllexport) unsigned int shutdown_state;
static BOOLEAN (WINAPI *shutdown_query)(void);

__declspec(dllexport) unsigned int Query(void)
{
	return base_state;
}

__declspec(dllexport) void Record(unsigned int digit)
{
	base_state = base_state * 10 + digit;
}

BOOL WINAPI DllMain(HINSTANCE image, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		shutdown_query = (void *)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlDllShutdownInProgress");
		if (!shutdown_query || shutdown_query())
			return FALSE;
		if (!reserved || !NtCurrentTeb()->ProcessEnvironmentBlock->Ldr || GetModuleHandleA("base.dll") != image)
			return FALSE;
		base_state = 11;
	} else if (reason == DLL_PROCESS_DETACH) {
		shutdown_state = shutdown_query() ? 1 : 0;
		Record(4);
	}
	return TRUE;
}

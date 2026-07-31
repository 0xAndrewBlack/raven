#include <windows.h>
#include <winternl.h>

__declspec(dllexport) unsigned int base_state;

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
		if (!reserved || !NtCurrentTeb()->ProcessEnvironmentBlock->Ldr || GetModuleHandleA("base.dll") != image)
			return FALSE;
		base_state = 11;
	} else if (reason == DLL_PROCESS_DETACH) {
		Record(4);
	}
	return TRUE;
}

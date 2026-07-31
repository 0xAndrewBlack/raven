#include <windows.h>

__declspec(dllimport) unsigned int Query(void);
__declspec(dllimport) void Record(unsigned int digit);
__declspec(dllexport) unsigned int dependent_state;

__declspec(dllexport) unsigned int DependentState(void)
{
	return dependent_state;
}

BOOL WINAPI DllMain(HINSTANCE image, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		if (!reserved || Query() != 11 || GetModuleHandleA("dependent.dll") != image)
			return FALSE;
		Record(2);
		dependent_state = 21;
	} else if (reason == DLL_PROCESS_DETACH) {
		Record(3);
		dependent_state = 210;
	}
	return TRUE;
}

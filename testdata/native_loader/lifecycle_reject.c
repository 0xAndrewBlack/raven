#include <windows.h>

__declspec(dllimport) void Record(unsigned int digit);
__declspec(dllexport) unsigned int reject_state;

BOOL WINAPI DllMain(HINSTANCE image, DWORD reason, LPVOID reserved)
{
	if (reason == DLL_PROCESS_ATTACH) {
		reject_state = 51;
		Record(5);
#if RAVEN_LOADER_MODE == 2
		__asm__("ud2");
#elif RAVEN_LOADER_MODE == 3
		for (;;) {}
#endif
		return FALSE;
	} else if (reason == DLL_PROCESS_DETACH) {
		Record(6);
		reject_state = reserved ? 511 : 510;
	}
	return TRUE;
}

#include <windows.h>

/* A redistributable library as an installer puts it in the system directory. */

__declspec(dllexport) int redist_magic(void)
{
	return 4242;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	(void)instance; (void)reason; (void)reserved;
	return TRUE;
}

#include <windows.h>

/* A library an installer writes into the system directory under the name of a system library and of a redistributable: the marker says
   whether a program got this file or the library the system provides. */

__declspec(dllexport) int RavenFakeMarker(void)
{
	return 42;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	return TRUE;
}

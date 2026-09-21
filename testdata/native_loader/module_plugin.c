#include <windows.h>

/* A library a program keeps in a folder of its own, as installer bootstrappers keep their user interface. */

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, void *reserved)
{
	return TRUE;
}

__declspec(dllexport) int plugin_answer(void)
{
	return 42;
}

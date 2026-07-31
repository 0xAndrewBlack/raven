#include <windows.h>

__declspec(dllexport) volatile DWORD entered;

DWORD raven_entry(void)
{
	HMODULE module = LoadLibraryA("probe.dll");
	entered = 1;
	if (!module)
		return GetLastError();
	if (!FreeLibrary(module))
		return 900;
	return 0;
}

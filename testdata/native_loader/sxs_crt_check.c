#include <windows.h>
#include <stdio.h>
#include <string.h>

/* A program built against the Visual C++ 2005 or 2008 runtime, which it names in its manifest as Windows programs of that time did: the
   runtime library comes from the side-by-side assembly the redistributable installed, never from the system directory, and runs.
   CRT_NAME is the library and CRT_VERSION its major version. */

int raven_entry(void)
{
	HMODULE runtime = GetModuleHandleW(CRT_NAME);
	if (!runtime)
		return 1;
	WCHAR path[MAX_PATH];
	if (!GetModuleFileNameW(runtime, path, MAX_PATH))
		return 2;
	CharLowerW(path);
	if (!wcsstr(path, L"\\winsxs\\x86_microsoft.vc" CRT_VERSION "0.crt_1fc8b3b9a1e18e3b_"))
		return 3;
	/* The runtime's own formatting runs: the library is not only mapped but initialized. */
	char text[32];
	if (_snprintf(text, sizeof text, "%d-%s", 42, "sxs") != 6 || strcmp(text, "42-sxs"))
		return 4;
	return 0;
}

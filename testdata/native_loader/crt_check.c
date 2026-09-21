#include <windows.h>
#include <stdio.h>
#include <string.h>

/* A program built against one Visual C++ runtime from 2005 to 2013, as Windows programs of that time were: CRT_NAME is the runtime
   library, which must come from the place CRT_PLACE names, lower case, and run. The 2005 and 2008 runtimes come from the side-by-side
   assembly the program's manifest names, the later ones from the system directory. */

int raven_entry(void)
{
	HMODULE runtime = GetModuleHandleW(CRT_NAME);
	if (!runtime)
		return 1;
	WCHAR path[MAX_PATH];
	if (!GetModuleFileNameW(runtime, path, MAX_PATH))
		return 2;
	CharLowerW(path);
	if (!wcsstr(path, CRT_PLACE))
		return 3;
	/* The runtime's own formatting runs: the library is not only mapped but initialized. */
	char text[32];
	if (_snprintf(text, sizeof text, "%d-%s", 42, "crt") != 6 || strcmp(text, "42-crt"))
		return 4;
	return 0;
}

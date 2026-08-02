/* Loads the library named on the command line and returns the last error when it fails. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
int raven_entry(void)
{
	const char *line = GetCommandLineA();
	while (*line && *line != ' ') ++line;
	while (*line == ' ') ++line;
	static char path[512]; int n = 0;
	for (; *line && n < 500; ++line) if (*line != '"') path[n++] = *line;
	HMODULE m = LoadLibraryA(path);
	return m ? 0 : (int)GetLastError();
}

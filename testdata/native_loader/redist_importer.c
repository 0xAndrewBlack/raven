#include <windows.h>

/* A program that imports the redistributable library by name, as one installed after it would. */

__declspec(dllimport) int redist_magic(void);

int raven_entry(void)
{
	return redist_magic() == 4242 ? 0 : 1;
}

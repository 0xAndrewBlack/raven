#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	const WCHAR expected[]=L"\"arguments.exe\" \"\" \"plain\" \"with space\" \"a\\\"b\" \"C:\\tail\\\\\" \"--\"";
	const WCHAR *command=GetCommandLineW();
	for(unsigned i=0;i<sizeof(expected)/sizeof(expected[0]);++i)
		if(command[i]!=expected[i]) return 1;
	return 0;
}

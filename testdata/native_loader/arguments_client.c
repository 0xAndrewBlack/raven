#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	// The program is named by its drive-qualified path; only the arguments after it are fixed.
	const WCHAR image[]=L"arguments.exe\"";
	// Arguments are quoted only when they need it, as Windows programs write them.
	const WCHAR expected[]=L" \"\" plain \"with space\" \"a\\\"b\" C:\\tail\\ --";
	const WCHAR *command=GetCommandLineW();
	unsigned at=0;
	if(command[at++]!=L'"') return 1;
	while(command[at] && command[at]!=L'"') ++at;
	if(command[at]!=L'"' || at<sizeof(image)/sizeof(image[0])-1) return 2;
	++at;
	for(unsigned i=0;i<sizeof(image)/sizeof(image[0])-1;++i)
		if(command[at-sizeof(image)/sizeof(image[0])+1+i]!=image[i]) return 3;
	for(unsigned i=0;i<sizeof(expected)/sizeof(expected[0]);++i)
		if(command[at+i]!=expected[i]) return 4;
	return 0;
}

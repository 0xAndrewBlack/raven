#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	static const char text[]="x86 native\n";
	DWORD count=0;
	SetLastError(0x1234);
	if (GetLastError()!=0x1234) ExitProcess(1);
	if (!GetCurrentProcessId() || GetCurrentThreadId()!=1) ExitProcess(2);
	const char *command=GetCommandLineA();
	if (!command || command[0]!='"') ExitProcess(3);
	HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
	if (!output || output==INVALID_HANDLE_VALUE) ExitProcess(4);
	if (!WriteFile(output,text,sizeof(text)-1,&count,0) || count!=sizeof(text)-1) ExitProcess(5);
	ExitProcess(73);
	return 0;
}

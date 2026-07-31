#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	const BYTE bytes[]={'A',0,'B','\n'};
	DWORD count=0xaaaa;
	SetLastError(0x5678);
	HANDLE output=GetStdHandle(STD_OUTPUT_HANDLE);
	if (!output || output==INVALID_HANDLE_VALUE || GetStdHandle(STD_OUTPUT_HANDLE)!=output || GetLastError()!=0x5678) return 1;
	if (GetFileType(output)!=FILE_TYPE_DISK) return 2;
	STARTUPINFOA startup;
	GetStartupInfoA(&startup);
	if ((startup.dwFlags & STARTF_USESTDHANDLES) && startup.hStdOutput!=output) return 3;
	if (!WriteFile(output,bytes,sizeof(bytes),&count,0) || count!=sizeof(bytes)) return 4;
	if (!WriteFile(output,bytes,0,&count,0) || count) return 5;
	const DWORD invalid[]={0,1,(DWORD)-13,(DWORD)-9};
	for (unsigned i=0;i<sizeof(invalid)/sizeof(invalid[0]);++i) {
		SetLastError(0);
		if (GetStdHandle(invalid[i])!=INVALID_HANDLE_VALUE || GetLastError()!=ERROR_INVALID_HANDLE) return 6;
	}
	HANDLE event=CreateEventW(0,TRUE,FALSE,0);
	if (!event || GetFileType(event)!=FILE_TYPE_UNKNOWN || GetLastError()!=ERROR_INVALID_HANDLE || !CloseHandle(event)) return 7;
	if (!CloseHandle(output) || GetStdHandle(STD_OUTPUT_HANDLE)!=output) return 8;
	count=0xaaaa;
	if (WriteFile(output,bytes,sizeof(bytes),&count,0) || GetLastError()!=ERROR_INVALID_HANDLE || count) return 9;
	return 0;
}

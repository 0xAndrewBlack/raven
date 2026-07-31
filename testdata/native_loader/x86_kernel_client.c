#define WIN32_LEAN_AND_MEAN
#include <windows.h>

int raven_entry(void)
{
	static const WCHAR text[]={'r','a','v','e','n',0};
	WCHAR copy[8];
	char path[64];
	if (lstrlenW(text)!=5 || lstrcpyW(copy,text)!=copy || copy[4]!='n' || copy[5]) return 1;
	if (GetModuleHandleA(0)!=(HMODULE)0x400000) return 2;
	HMODULE kernel=GetModuleHandleA("kernel32.dll");
	if (!kernel || GetModuleHandleA("missing.dll") || GetLastError()!=ERROR_MOD_NOT_FOUND) return 3;
	DWORD (WINAPI *ticks)(void)=(DWORD (WINAPI *)(void))GetProcAddress(kernel,"GetTickCount");
	if (!ticks || GetProcAddress(kernel,"NoSuchExport") || GetLastError()!=ERROR_PROC_NOT_FOUND) return 4;
	DWORD first=ticks();
	if (GetTickCount()<first) return 5;
	DWORD length=GetModuleFileNameA(0,path,sizeof(path));
	if (!length || path[length]) return 6;
	STARTUPINFOA startup;
	startup.cb=0;
	GetStartupInfoA(&startup);
	if (startup.cb!=sizeof(startup)) return 7;
	BYTE *memory=(BYTE *)VirtualAlloc(0,8192,MEM_RESERVE|MEM_COMMIT,PAGE_READWRITE);
	if (!memory || (DWORD)(DWORD_PTR)memory>=0x80000000) return 8;
	memory[0]=0x5a;memory[8191]=0xa5;
	DWORD old=0;
	if (!VirtualProtect(memory,4096,PAGE_READONLY,&old) || old!=PAGE_READWRITE || memory[0]!=0x5a) return 9;
	if (!VirtualFree(memory,0,MEM_RELEASE)) return 10;
	return 0;
}

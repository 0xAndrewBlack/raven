#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifndef RAVEN_PHASE
#define RAVEN_PHASE 1
#endif

static int same(const char *left,const char *right)
{
	while (*left && *left==*right) { ++left; ++right; }
	return *left==*right;
}

int raven_entry(void)
{
	HKEY key=0,again=0;
	DWORD disposition=0,type=0,size=0,number=0;
	WCHAR text[16];
	char ansi[16];
	if (RAVEN_PHASE==1) {
		if (RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Raven\\Contract",0,0,0,KEY_ALL_ACCESS,0,&key,&disposition) || !key || disposition!=REG_CREATED_NEW_KEY) return 1;
		number=0x1234abcd;
		if (RegSetValueExW(key,L"Count",0,REG_DWORD,(const BYTE *)&number,sizeof(number))) return 2;
		if (RegSetValueExW(key,L"Name",0,REG_SZ,(const BYTE *)L"raven",12)) return 3;
		if (RegCloseKey(key) || !RegCloseKey(key)) return 4;
		if (RegCreateKeyExW(HKEY_CURRENT_USER,L"software\\RAVEN\\contract",0,0,0,KEY_ALL_ACCESS,0,&again,&disposition) || disposition!=REG_OPENED_EXISTING_KEY) return 5;
		RegCloseKey(again);
		return 0;
	}
	if (RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Raven\\Missing",0,KEY_READ,&key)!=ERROR_FILE_NOT_FOUND) return 10;
	if (RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Raven\\Contract",0,KEY_READ,&key) || !key) return 11;
	size=sizeof(number);
	if (RegQueryValueExW(key,L"COUNT",0,&type,(BYTE *)&number,&size) || type!=REG_DWORD || size!=4 || number!=0x1234abcd) return 12;
	size=2;
	if (RegQueryValueExW(key,L"Name",0,&type,(BYTE *)text,&size)!=ERROR_MORE_DATA || size!=12) return 13;
	size=sizeof(text);
	if (RegQueryValueExW(key,L"Name",0,&type,(BYTE *)text,&size) || type!=REG_SZ || size!=12 || text[0]!='r' || text[4]!='n' || text[5]) return 14;
	size=sizeof(ansi);
	if (RegQueryValueExA(key,"Name",0,&type,(BYTE *)ansi,&size) || type!=REG_SZ || size!=6 || !same(ansi,"raven")) return 15;
	size=0;
	if (RegQueryValueExW(key,L"Name",0,&type,0,&size) || size!=12) return 16;
	if (RegQueryValueExW(key,L"Nothing",0,&type,0,&size)!=ERROR_FILE_NOT_FOUND) return 17;
	RegCloseKey(key);
	return 0;
}

#include <windows.h>

extern unsigned char __ImageBase;
__declspec(dllimport) unsigned int Named(unsigned int value);
typedef unsigned int (*add_fn)(unsigned int);
typedef DWORD (WINAPI *error_fn)(void);

unsigned int raven_entry(void)
{
	SetLastError(123);
	if (GetModuleHandleA(NULL) != (HMODULE)&__ImageBase || GetModuleHandleW(NULL) != (HMODULE)&__ImageBase)
		return 1;
	HMODULE kernel = GetModuleHandleA("KeRnEl32");
	if (!kernel || kernel != GetModuleHandleW(L"kernel32.dll"))
		return 2;
	error_fn last_error = (error_fn)GetProcAddress(kernel, "GetLastError");
	if (!last_error || last_error() != 123)
		return 3;
	if (GetModuleHandleA("raven_missing.dll") || GetLastError() != ERROR_MOD_NOT_FOUND)
		return 4;
	if (GetProcAddress(kernel, "getlasterror") || GetLastError() != ERROR_PROC_NOT_FOUND)
		return 5;
	if (Named(10) != 15)
		return 6;
	HMODULE facade = GetModuleHandleA("facade.dll");
	HMODULE target = GetModuleHandleW(L"TARGET.DLL");
	add_fn named = (add_fn)GetProcAddress(facade, "Named");
	add_fn ordinal = (add_fn)GetProcAddress(facade, (LPCSTR)2);
	add_fn direct = (add_fn)GetProcAddress(target, (LPCSTR)7);
	if (!facade || !target || !named || !ordinal || !direct || named != direct || ordinal != direct)
		return 7;
	if (named(10) + ordinal(20) != 40)
		return 8;
	return 0;
}

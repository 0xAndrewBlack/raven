#define UNICODE
#include <windows.h>

__declspec(dllexport) volatile DWORD phase;
__declspec(dllexport) HRSRC resource_handle;
__declspec(dllexport) HGLOBAL resource_data;
__declspec(dllexport) HMODULE resource_module;

static int verify_resources(HMODULE module)
{
	SetLastError(71);
	HRSRC mixed = FindResourceW(module, L"MiXeD", RT_RCDATA);
	if (!mixed || mixed != FindResourceW(module, L"mixed", RT_RCDATA) ||
		mixed != FindResourceA(module, "MIXED", MAKEINTRESOURCEA(10)) || GetLastError() != 71)
		return 1;
	HGLOBAL data = LoadResource(module, mixed);
	const WORD *words = (const WORD *)LockResource(data);
	if (!data || (const void *)data != (const void *)words || SizeofResource(module, mixed) != 4 ||
		words[0] != 0x1234 || words[1] != 0x5678 || GetLastError() != 71)
		return 2;
	HRSRC english = FindResourceExW(module, RT_RCDATA, MAKEINTRESOURCEW(101), 0x409);
	HRSRC french = FindResourceExA(module, MAKEINTRESOURCEA(10), "#00101", 0x40c);
	if (!english || !french || english == french ||
		english != FindResourceExW(module, L"#10", L"#101", 0x409))
		return 3;
	const WORD *en = (const WORD *)LockResource(LoadResource(module, english));
	const WORD *fr = (const WORD *)LockResource(LoadResource(module, french));
	if (!en || !fr || en[0] != 0x3141 || en[1] != 0x5926 || fr[0] != 0x1618 || fr[1] != 0x0339)
		return 4;
	HRSRC neutral = FindResourceExW(module, RT_RCDATA, MAKEINTRESOURCEW(102), 0x409);
	if (!neutral || neutral != FindResourceW(module, L"#102", RT_RCDATA) ||
		!FindResourceW(module, MAKEINTRESOURCEW(103), RT_RCDATA))
		return 5;
	HRSRC custom = FindResourceW(module, MAKEINTRESOURCEW(7), L"custom");
	if (!custom || ((const WORD *)LockResource(LoadResource(module, custom)))[0] != 0x4242)
		return 6;
	if (FindResourceW(module, MAKEINTRESOURCEW(101), MAKEINTRESOURCEW(999)) || GetLastError() != ERROR_RESOURCE_TYPE_NOT_FOUND)
		return 7;
	if (FindResourceW(module, MAKEINTRESOURCEW(999), RT_RCDATA) || GetLastError() != ERROR_RESOURCE_NAME_NOT_FOUND)
		return 8;
	if (FindResourceExW(module, RT_RCDATA, MAKEINTRESOURCEW(103), 0x409) || GetLastError() != ERROR_RESOURCE_LANG_NOT_FOUND)
		return 9;
	resource_handle = mixed;
	resource_data = data;
	return 0;
}

int raven_entry(void)
{
	int result = verify_resources(0);
	if (result)
		return result;
	phase = 1;
	resource_module = LoadLibraryW(L"resources.dll");
	if (!resource_module)
		return 10;
	result = verify_resources(resource_module);
	if (result)
		return 20 + result;
	phase = 2;
	if (!FreeLibrary(resource_module))
		return 11;
	phase = 3;
	return 0;
}

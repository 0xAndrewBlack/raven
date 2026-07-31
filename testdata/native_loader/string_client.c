#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static int verify(HMODULE module)
{
	const UINT ids[] = {1, 2, 0, 3, 16, 0x10001, 0xffffffff};
	const int sizes[] = {0, 1, 2, 5, 6};
	const WCHAR first[] = {65, 233, 0, 20013, 66};
	const WCHAR second[] = {116, 97, 105, 108};
	for (unsigned j = 0; j < sizeof(ids) / sizeof(ids[0]); ++j)
		for (unsigned k = 0; k < sizeof(sizes) / sizeof(sizes[0]); ++k) {
			WCHAR buffer[16];
			for (unsigned i = 0; i < 16; ++i) buffer[i] = 0x5a5a;
			const WCHAR *pointer = (const WCHAR *)(ULONG_PTR)0x12345;
			const UINT id = ids[j] & 0xffff;
			const BOOL missing = id == 16 || id == 0xffff;
			const unsigned length = id == 1 ? 5 : id == 2 ? 4 : 0;
			const WCHAR *expected = id == 2 ? second : first;
			SetLastError(0x7654);
			int result = LoadStringW(module, ids[j], sizes[k] ? buffer : (WCHAR *)&pointer, sizes[k]);
			if (GetLastError() != (missing ? ERROR_RESOURCE_NAME_NOT_FOUND : 0x7654)) return 1;
			if (!sizes[k]) {
				if (result != (int)length) return 2;
				if (missing) {
					if (pointer != (const WCHAR *)(ULONG_PTR)0x12345) return 3;
				} else {
					if (!pointer || pointer == (const WCHAR *)(ULONG_PTR)0x12345) return 4;
					for (unsigned i = 0; i < length; ++i) if (pointer[i] != expected[i]) return 5;
					HRSRC info = FindResourceW(module, MAKEINTRESOURCEW(1), RT_STRING);
					const BYTE *table = (const BYTE *)LockResource(LoadResource(module, info));
					if ((const BYTE *)pointer < table || (const BYTE *)pointer >= table + SizeofResource(module, info)) return 6;
				}
				for (unsigned i = 0; i < 16; ++i) if (buffer[i] != 0x5a5a) return 7;
			} else {
				unsigned count = length < (unsigned)sizes[k] ? length : (unsigned)sizes[k] - 1;
				if (result != (int)count || buffer[count]) return 8;
				for (unsigned i = 0; i < count; ++i) if (buffer[i] != expected[i]) return 9;
				for (unsigned i = count + 1; i < 16; ++i) if (buffer[i] != 0x5a5a) return 10;
			}
		}
	return 0;
}

int raven_entry(void)
{
	int result = verify(NULL);
	if (result) return result;
	result = verify(GetModuleHandleW(NULL));
	if (result) return result + 20;
	HMODULE module = LoadLibraryW(L"strings.dll");
	if (!module) return 40;
	result = verify(module);
	if (result) return result + 40;
	if (!FreeLibrary(module)) return 60;
	return 0;
}

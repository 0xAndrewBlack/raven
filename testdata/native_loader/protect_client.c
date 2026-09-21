#include <windows.h>

/* The system's libraries stay the system's: with --install the program acts as an installer that writes its own files over kernel32.dll
   and msvcr120.dll in the system directory, which must be accepted. Run without it, the program checks that the file's version is the
   one written, that kernel32 is still the system's library, and that the redistributable now loads from the file the installer left. */

static int copy_beside(const WCHAR *system, const WCHAR *name)
{
	WCHAR source[MAX_PATH], target[MAX_PATH];
	DWORD length = GetModuleFileNameW(NULL, source, MAX_PATH);
	while (length && source[length - 1] != L'\\')
		--length;
	lstrcpyW(source + length, L"fake-library.dll");
	lstrcpyW(target, system);
	lstrcatW(target, L"\\");
	lstrcatW(target, name);
	return CopyFileW(source, target, FALSE);
}

int raven_entry(void)
{
	WCHAR system[MAX_PATH], kernel[MAX_PATH];
	if (!GetSystemDirectoryW(system, MAX_PATH))
		return 1;
	const WCHAR *line = GetCommandLineW();
	BOOL install = FALSE;
	for (; *line; ++line)
		if (line[0] == L'-' && line[1] == L'-' && line[2] == L'i')
			install = TRUE;
	if (install)
		return copy_beside(system, L"kernel32.dll") && copy_beside(system, L"msvcr120.dll") ? 0 : 2;
	/* The version read from the file is the version of the file there. */
	lstrcpyW(kernel, system);
	lstrcatW(kernel, L"\\kernel32.dll");
	static BYTE block[4096];
	VS_FIXEDFILEINFO *fixed = NULL;
	UINT size = 0;
	if (!GetFileVersionInfoW(kernel, 0, sizeof block, block) || !VerQueryValueW(block, L"\\", (void **)&fixed, &size) ||
		HIWORD(fixed->dwFileVersionMS) != 99)
		return 10;
	/* kernel32 is the system's whatever file carries its name. */
	HMODULE system_library = LoadLibraryW(L"kernel32.dll");
	if (!system_library || GetProcAddress(system_library, "RavenFakeMarker") || !GetProcAddress(system_library, "GetTickCount"))
		return 11;
	/* The redistributable is the file the installer put there. */
	HMODULE redistributable = LoadLibraryW(L"msvcr120.dll");
	if (!redistributable || !GetProcAddress(redistributable, "RavenFakeMarker"))
		return 12;
	return 0;
}

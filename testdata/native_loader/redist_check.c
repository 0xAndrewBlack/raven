#include <windows.h>

/* What a Visual C++ redistributable leaves behind, seen by a program: the runtime key Windows programs and installers test, and the
   runtime library found by name in the system directory, where the redistributable put it. With --removed, both must be gone. */

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW();
	BOOL removed = FALSE;
	for (; *line; ++line)
		if (line[0] == L'-' && line[1] == L'-' && line[2] == L'r')
			removed = TRUE;
#ifdef _WIN64
	const WCHAR *key = L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x64";
	const WCHAR *expected = L"C:\\Windows\\System32\\vcruntime140.dll";
#else
	const WCHAR *key = L"SOFTWARE\\Microsoft\\VisualStudio\\14.0\\VC\\Runtimes\\x86";
	const WCHAR *expected = L"C:\\Windows\\SysWOW64\\vcruntime140.dll";
#endif
	/* The key is in the registry view of the runtime's width; either view counts, as programs of both widths look for it. */
	BOOL registered = FALSE;
	for (int view = 0; view < 2 && !registered; ++view) {
		HKEY handle;
		DWORD installed = 0, size = sizeof installed;
		if (!RegOpenKeyExW(HKEY_LOCAL_MACHINE, key, 0, KEY_READ | (view ? KEY_WOW64_32KEY : KEY_WOW64_64KEY), &handle)) {
			registered = !RegQueryValueExW(handle, L"Installed", NULL, NULL, (BYTE *)&installed, &size) && installed == 1;
			RegCloseKey(handle);
		}
	}
	/* After removal the file is gone; loading by name could still find the runtime's own copy, so the file itself is what is checked. */
	if (removed)
		return registered ? 1 : GetFileAttributesW(expected) != INVALID_FILE_ATTRIBUTES ? 2 : 0;
	HMODULE runtime = LoadLibraryW(L"vcruntime140.dll");
	if (!registered)
		return 3;
	if (!runtime)
		return 4;
	WCHAR path[MAX_PATH];
	if (!GetModuleFileNameW(runtime, path, MAX_PATH) || lstrcmpiW(path, expected))
		return 5;
	if (!GetProcAddress(runtime, "__CxxFrameHandler3"))
		return 6;
	return 0;
}

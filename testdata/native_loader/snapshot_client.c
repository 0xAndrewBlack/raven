#include <windows.h>

/* An installation the prefix can be taken back from: with --install the program leaves a file on the system drive and a value in the
   registry. Otherwise it reports whether they are there: with --present it succeeds when both are, without it when neither is. */

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW();
	BOOL install = FALSE, present = FALSE;
	for (; *line; ++line)
		if (line[0] == L'-' && line[1] == L'-') {
			install |= line[2] == L'i';
			present |= line[2] == L'p';
		}
	HKEY key;
	if (install) {
		HANDLE file = CreateFileW(L"C:\\snapshot-marker.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (file == INVALID_HANDLE_VALUE)
			return 1;
		CloseHandle(file);
		if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\RavenSnapshot", 0, NULL, 0, KEY_WRITE, NULL, &key, NULL))
			return 2;
		const DWORD value = 1;
		const LONG written = RegSetValueExW(key, L"Installed", 0, REG_DWORD, (const BYTE *)&value, sizeof value);
		RegCloseKey(key);
		return written ? 3 : 0;
	}
	const BOOL file = GetFileAttributesW(L"C:\\snapshot-marker.txt") != INVALID_FILE_ATTRIBUTES;
	const BOOL registered = !RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\RavenSnapshot", 0, KEY_READ, &key);
	if (registered)
		RegCloseKey(key);
	if (present)
		return file && registered ? 0 : 4;
	return !file && !registered ? 0 : 5;
}

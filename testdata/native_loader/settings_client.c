#include <windows.h>
#include <uxtheme.h>

/* Settings kept the way the control panel keeps them: one run switches the visual styles off in the registry, as Windows records it, and
   a program started afterwards finds them off. */

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW();
	const WCHAR *key = L"Software\\Microsoft\\Windows\\CurrentVersion\\ThemeManager";
	BOOL write = FALSE;
	for (; *line; ++line)
		if (line[0] == L'-' && line[1] == L'-' && line[2] == L'w')
			write = TRUE;
	if (write) {
		HKEY handle;
		if (RegCreateKeyExW(HKEY_CURRENT_USER, key, 0, NULL, 0, KEY_WRITE, NULL, &handle, NULL))
			return 1;
		if (RegSetValueExW(handle, L"ThemeActive", 0, REG_SZ, (const BYTE *)L"0", 2 * sizeof(WCHAR)))
			return 2;
		RegCloseKey(handle);
		/* The program that changed the setting keeps the styles it started with. */
		return IsThemeActive() ? 0 : 3;
	}
	return IsThemeActive() ? 4 : 0;
}

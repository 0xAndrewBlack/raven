#include <windows.h>

/* Work left for the next start of Windows. With --schedule the program, as an installer would, asks for one file to be moved and one
   deleted at the restart and for itself to run once at the next logon; nothing changes before the restart. With --runonce it is that
   run and leaves a mark. Without arguments, after the restart, it checks that all of it happened and that the RunOnce entry is gone. */

static BOOL exists(const WCHAR *path)
{
	return GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES;
}

static BOOL create(const WCHAR *path)
{
	HANDLE file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return FALSE;
	CloseHandle(file);
	return TRUE;
}

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW();
	BOOL schedule = FALSE, run_once = FALSE;
	for (; *line; ++line)
		if (line[0] == L'-' && line[1] == L'-') {
			schedule |= line[2] == L's';
			run_once |= line[2] == L'r';
		}
	if (run_once)
		return create(L"C:\\pending-runonce.txt") ? 0 : 1;
	HKEY key;
	if (schedule) {
		WCHAR self[MAX_PATH];
		if (!GetModuleFileNameW(NULL, self, MAX_PATH) || !CopyFileW(self, L"C:\\pending-check.exe", FALSE))
			return 2;
		if (!create(L"C:\\pending-old.txt") || !create(L"C:\\pending-gone.txt"))
			return 3;
		if (!MoveFileExW(L"C:\\pending-old.txt", L"C:\\pending-new.txt", MOVEFILE_DELAY_UNTIL_REBOOT) ||
			!MoveFileExW(L"C:\\pending-gone.txt", NULL, MOVEFILE_DELAY_UNTIL_REBOOT))
			return 4;
		if (RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, NULL, 0, KEY_WRITE, NULL, &key, NULL))
			return 5;
		const WCHAR command[] = L"\"C:\\pending-check.exe\" --runonce";
		const LONG written = RegSetValueExW(key, L"RavenPending", 0, REG_SZ, (const BYTE *)command, sizeof command);
		RegCloseKey(key);
		if (written)
			return 6;
		/* Nothing moves before the restart. */
		return exists(L"C:\\pending-old.txt") && !exists(L"C:\\pending-new.txt") && exists(L"C:\\pending-gone.txt") ? 0 : 7;
	}
	if (exists(L"C:\\pending-old.txt") || !exists(L"C:\\pending-new.txt") || exists(L"C:\\pending-gone.txt"))
		return 8;
	if (!exists(L"C:\\pending-runonce.txt"))
		return 9;
	if (!RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, KEY_READ, &key)) {
		const LONG found = RegQueryValueExW(key, L"RavenPending", NULL, NULL, NULL, NULL);
		RegCloseKey(key);
		if (!found)
			return 10;
	}
	return 0;
}

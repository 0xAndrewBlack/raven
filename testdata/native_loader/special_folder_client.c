#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>

int raven_entry(void)
{
	const int folders[] = {CSIDL_APPDATA, CSIDL_LOCAL_APPDATA, CSIDL_PERSONAL, CSIDL_PROGRAM_FILES};
	char ansi[MAX_PATH + 1], converted[MAX_PATH];
	WCHAR wide[MAX_PATH + 1], expected[MAX_PATH];
	for (unsigned index = 0; index < sizeof(folders) / sizeof(folders[0]); ++index) {
		ansi[MAX_PATH] = 0x5a;
		wide[MAX_PATH] = 0x5a;
		if (!SHGetSpecialFolderPathA(NULL, ansi, folders[index], TRUE) ||
			!SHGetSpecialFolderPathW(NULL, wide, folders[index], TRUE))
			return 1;
		if (SHGetFolderPathW(NULL, folders[index], NULL, 0, expected) != S_OK || lstrcmpW(wide, expected) ||
			!WideCharToMultiByte(CP_ACP, 0, wide, -1, converted, MAX_PATH, NULL, NULL) || lstrcmpA(ansi, converted))
			return 2;
		if (ansi[MAX_PATH] != 0x5a || wide[MAX_PATH] != 0x5a)
			return 3;
	}
	if (SHGetSpecialFolderPathA(NULL, ansi, CSIDL_DRIVES, FALSE) || SHGetSpecialFolderPathW(NULL, wide, 0x7fff, FALSE))
		return 4;
	if (SHGetFolderPathW(NULL, CSIDL_TEMPLATES, NULL, 0, expected) != S_OK)
		return 5;
	RemoveDirectoryW(expected);
	SHGetSpecialFolderPathA(NULL, ansi, CSIDL_TEMPLATES, FALSE);
	if (GetFileAttributesW(expected) != INVALID_FILE_ATTRIBUTES)
		return 6;
	if (!SHGetSpecialFolderPathA(NULL, ansi, CSIDL_TEMPLATES, TRUE) ||
		!(GetFileAttributesW(expected) & FILE_ATTRIBUTE_DIRECTORY) || !RemoveDirectoryW(expected))
		return 7;
	HANDLE file = CreateFileW(expected, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE)
		return 8;
	CloseHandle(file);
	if (SHGetSpecialFolderPathA(NULL, ansi, CSIDL_TEMPLATES, TRUE) || SHGetSpecialFolderPathW(NULL, wide, CSIDL_TEMPLATES, TRUE))
		return 9;
	DeleteFileW(expected);
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* An installer copies a redistributable library into the system directory, and copies over system libraries as some do. The
   redistributable is then found there by name, by a later program's imports and by LoadLibrary, while the system libraries stay
   the runtime's own whatever the files in the system directory hold. */

typedef int (*magic_fn)(void);

static unsigned length(const WCHAR *text)
{
	unsigned count = 0;
	while (text[count])
		++count;
	return count;
}

static void join(WCHAR *target, const WCHAR *directory, const WCHAR *name)
{
	unsigned at = 0;
	for (unsigned i = 0; directory[i]; ++i)
		target[at++] = directory[i];
	target[at++] = L'\\';
	for (unsigned i = 0; name[i]; ++i)
		target[at++] = name[i];
	target[at] = 0;
}

static BOOL same(const WCHAR *a, const WCHAR *b)
{
	for (;; ++a, ++b) {
		WCHAR x = *a >= L'A' && *a <= L'Z' ? *a + 32 : *a, y = *b >= L'A' && *b <= L'Z' ? *b + 32 : *b;
		if (x != y)
			return FALSE;
		if (!x)
			return TRUE;
	}
}

int raven_entry(void)
{
	WCHAR program[MAX_PATH], directory[MAX_PATH], system[MAX_PATH], payload[MAX_PATH], target[MAX_PATH], path[MAX_PATH];
	if (!GetModuleFileNameW(NULL, program, MAX_PATH) || !GetSystemDirectoryW(system, MAX_PATH))
		return 1;
	unsigned cut = length(program);
	while (cut && program[cut - 1] != L'\\')
		--cut;
	for (unsigned i = 0; i + 1 < cut; ++i)
		directory[i] = program[i];
	directory[cut ? cut - 1 : 0] = 0;
	join(path, directory, L"payload");
	join(payload, path, L"ravenredist.dll");
	/* The library is not beside the program: only the system directory has it, once installed. A prefix used before starts over. */
	join(target, system, L"ravenredist.dll");
	DeleteFileW(target);
	if (LoadLibraryW(L"ravenredist.dll") || GetLastError() != ERROR_MOD_NOT_FOUND)
		return 2;
	join(target, system, L"ravenredist.dll");
	if (!CopyFileW(payload, target, FALSE))
		return 3;
	join(target, system, L"kernel32.dll");
	if (!CopyFileW(payload, target, FALSE))
		return 4;
	join(target, system, L"oleaut32.dll");
	if (!CopyFileW(payload, target, FALSE))
		return 5;

	HMODULE kernel = GetModuleHandleW(L"kernel32.dll");
	if (!kernel || LoadLibraryW(L"kernel32.dll") != kernel)
		return 6;
	join(target, system, L"kernel32.dll");
	if (LoadLibraryW(target) != kernel)
		return 7;
	if (GetProcAddress(kernel, "redist_magic") || !GetProcAddress(kernel, "GetTickCount"))
		return 8;
	HMODULE automation = LoadLibraryW(L"oleaut32.dll");
	if (!automation || GetProcAddress(automation, "redist_magic") || !GetProcAddress(automation, "SysAllocString"))
		return 9;

	HMODULE redist = LoadLibraryW(L"ravenredist.dll");
	if (!redist)
		return 10;
	magic_fn magic = (magic_fn)GetProcAddress(redist, "redist_magic");
	if (!magic || magic() != 4242)
		return 11;
	/* A 32-bit program finds it in SysWOW64, where its view of the system directory leads. */
#ifdef _WIN64
	join(target, system, L"ravenredist.dll");
#else
	join(target, L"C:\\Windows\\SysWOW64", L"ravenredist.dll");
#endif
	if (!GetModuleFileNameW(redist, path, MAX_PATH) || !same(path, target))
		return 12;

	/* A program started afterwards imports it by name. */
	join(path, directory, L"redist-importer.exe");
	STARTUPINFOW startup = {sizeof startup};
	PROCESS_INFORMATION process;
	if (!CreateProcessW(path, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process))
		return 13;
	DWORD code = 99;
	if (WaitForSingleObject(process.hProcess, 60000) != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &code))
		return 14;
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	if (code)
		return 20 + (int)code;
	return 0;
}

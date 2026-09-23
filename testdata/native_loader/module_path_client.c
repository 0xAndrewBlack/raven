#include <windows.h>
#include <lzexpand.h>

/* A library loaded by its full path from a folder beside the program reports that path as its file name, so it finds the files it ships
   with; and a process it starts can open it to wait on it, as a bootstrapper's elevated half watches the half that started it. The
   child's exit code reaches the parent whole, as an installer's 1603 does. */

static int child(const WCHAR *digits)
{
	DWORD parent = 0;
	while (*digits >= L'0' && *digits <= L'9')
		parent = parent * 10 + (DWORD)(*digits++ - L'0');
	HANDLE process = OpenProcess(SYNCHRONIZE, FALSE, parent);
	if (!process)
		return 20;
	CloseHandle(process);
	return 1603;
}

int raven_entry(void)
{
	WCHAR self[MAX_PATH], path[MAX_PATH], reported[MAX_PATH], command[MAX_PATH + 64];
	const WCHAR *line = GetCommandLineW();
	for (const WCHAR *at = line; *at; ++at)
		if (at[0] == L' ' && at[1] == L'-' && at[2] == L'-' && at[3] == L'c' && at[4] == L' ')
			return child(at + 5);
	if (!GetModuleFileNameW(NULL, self, MAX_PATH))
		return 1;
	lstrcpyW(path, self);
	WCHAR *slash = path;
	for (WCHAR *at = path; *at; ++at)
		if (*at == L'\\')
			slash = at;
	lstrcpyW(slash + 1, L"plugins\\module_plugin.dll");
	HMODULE plugin = LoadLibraryW(path);
	if (!plugin)
		return 2;
	if (!GetModuleFileNameW(plugin, reported, MAX_PATH) || lstrcmpiW(reported, path))
		return 3;
	int (*answer)(void) = (int (*)(void))GetProcAddress(plugin, "plugin_answer");
	if (!answer || answer() != 42)
		return 4;
	wsprintfW(command, L"\"%s\" --c %u", self, GetCurrentProcessId());
	STARTUPINFOW startup = {sizeof startup};
	PROCESS_INFORMATION started;
	if (!CreateProcessW(self, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &started))
		return 5;
	DWORD code = 1;
	if (WaitForSingleObject(started.hProcess, 30000) != WAIT_OBJECT_0 || !GetExitCodeProcess(started.hProcess, &code))
		return 6;
	CloseHandle(started.hThread);
	CloseHandle(started.hProcess);
	return code == 1603 ? 0 : 7;
}

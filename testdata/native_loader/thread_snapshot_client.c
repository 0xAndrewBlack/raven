#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>

static DWORD WINAPI worker(void *argument)
{
	(void)argument;
	return 0;
}

static int find_thread(HANDLE snapshot, DWORD owner, DWORD id, LONG priority)
{
	THREADENTRY32 entry = {sizeof(entry)};
	BOOL more = Thread32First(snapshot, &entry);
	int found = 0;
	while (more) {
		if (entry.dwSize != sizeof(entry) || entry.cntUsage || entry.tpDeltaPri || entry.dwFlags)
			return -1;
		if (entry.th32OwnerProcessID == owner && entry.th32ThreadID == id) {
			if (entry.tpBasePri != priority || found)
				return -1;
			found = 1;
		}
		more = Thread32Next(snapshot, &entry);
	}
	return GetLastError() == ERROR_NO_MORE_FILES ? found : -1;
}

int raven_entry(void)
{
	DWORD id, later_id;
	HANDLE thread = CreateThread(NULL, 0, worker, NULL, CREATE_SUSPENDED, &id);
	if (!thread || !SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL))
		return 1;
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0xffffffff);
	if (snapshot == INVALID_HANDLE_VALUE || find_thread(snapshot, GetCurrentProcessId(), GetCurrentThreadId(), 8) != 1 ||
		find_thread(snapshot, GetCurrentProcessId(), id, 9) != 1)
		return 2;
	struct { THREADENTRY32 entry; DWORD sentinel; } oversized = {{sizeof(oversized)}, 0x12345678};
	if (!Thread32First(snapshot, &oversized.entry) || oversized.entry.dwSize != sizeof(THREADENTRY32) || oversized.sentinel != 0x12345678)
		return 3;
	THREADENTRY32 entry = {0};
	if (Thread32First(snapshot, &entry) || GetLastError() != ERROR_BAD_LENGTH)
		return 4;
	entry.dwSize = sizeof(entry);
	if (Thread32First(INVALID_HANDLE_VALUE, &entry) || GetLastError() != ERROR_INVALID_HANDLE)
		return 5;
	HANDLE empty = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (empty == INVALID_HANDLE_VALUE || Thread32First(empty, &entry) || GetLastError() != ERROR_NO_MORE_FILES)
		return 6;
	CloseHandle(empty);
	HANDLE later = CreateThread(NULL, 0, worker, NULL, CREATE_SUSPENDED, &later_id);
	if (!later || find_thread(snapshot, GetCurrentProcessId(), later_id, 8) != 0 || !TerminateThread(thread, 0))
		return 7;
	if (find_thread(snapshot, GetCurrentProcessId(), id, 9) != 1)
		return 8;
	HANDLE current = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (current == INVALID_HANDLE_VALUE || find_thread(current, GetCurrentProcessId(), id, 9) != 0 ||
		find_thread(current, GetCurrentProcessId(), later_id, 8) != 1)
		return 9;
	CloseHandle(current);
	TerminateThread(later, 0);
	CloseHandle(later);
	CloseHandle(thread);
	CloseHandle(snapshot);
	WCHAR path[MAX_PATH];
	STARTUPINFOW startup = {sizeof(startup)};
	PROCESS_INFORMATION child;
	if (!GetModuleFileNameW(NULL, path, MAX_PATH) || !CreateProcessW(path, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child))
		return 10;
	HANDLE peers = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
	int result = peers != INVALID_HANDLE_VALUE && GetThreadId(child.hThread) == child.dwThreadId &&
		find_thread(peers, child.dwProcessId, child.dwThreadId, 8) == 1;
	TerminateProcess(child.hProcess, 0);
	WaitForSingleObject(child.hProcess, 5000);
	CloseHandle(child.hThread);
	CloseHandle(child.hProcess);
	if (peers != INVALID_HANDLE_VALUE)
		CloseHandle(peers);
	return result ? 0 : 11;
}

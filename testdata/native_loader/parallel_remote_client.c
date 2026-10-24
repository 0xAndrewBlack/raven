#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static volatile LONG ready, request, acknowledged, stop;
static volatile ULONG_PTR remote_pointer;
static volatile LONG counters[2];
static PROCESS_INFORMATION child;

static DWORD WINAPI compute(void *parameter)
{
	(void)parameter;
	InterlockedIncrement(&ready);
	while (!stop) InterlockedIncrement(&counters[1]);
	return 0;
}

static int parent(void)
{
	WCHAR command[1024];
	STARTUPINFOW startup = {sizeof(startup)};
	command[0] = '"';
	DWORD length = GetModuleFileNameW(0, command + 1, 1000);
	if (!length || length >= 1000) return 1;
	command[++length] = '"';
	command[++length] = ' ';
	command[++length] = 'c';
	command[++length] = 0;
	if (!CreateProcessW(0, command, 0, 0, FALSE, 0, 0, 0, &startup, &child)) return 2;
	LONG value = 0;
	for (unsigned i = 0; value != 2 && i < 1000; ++i) {
		if (!ReadProcessMemory(child.hProcess, (void *)&ready, &value, sizeof(value), 0)) return 3;
		Sleep(1);
	}
	if (value != 2) return 4;
	void *allocation = VirtualAllocEx(child.hProcess, 0, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocation) return 5;
	DWORD magic = 0x13579bdf, previous;
	if (!WriteProcessMemory(child.hProcess, allocation, &magic, sizeof(magic), 0)) return 6;
	if (!VirtualProtectEx(child.hProcess, allocation, 4096, PAGE_READONLY, &previous) || previous != PAGE_READWRITE) return 7;
	MEMORY_BASIC_INFORMATION information;
	if (!VirtualQueryEx(child.hProcess, allocation, &information, sizeof(information)) || information.Protect != PAGE_READONLY) return 8;
	ULONG_PTR pointer = (ULONG_PTR)allocation;
	if (!WriteProcessMemory(child.hProcess, (void *)&remote_pointer, &pointer, sizeof(pointer), 0)) return 9;
	value = 1;
	if (!WriteProcessMemory(child.hProcess, (void *)&request, &value, sizeof(value), 0)) return 10;
	value = 0;
	for (unsigned i = 0; !value && i < 1000; ++i) {
		if (!ReadProcessMemory(child.hProcess, (void *)&acknowledged, &value, sizeof(value), 0)) return 11;
		Sleep(1);
	}
	if (value != 1) return 12;
	if (!VirtualFreeEx(child.hProcess, allocation, 0, MEM_RELEASE)) return 13;
	value = 1;
	if (!WriteProcessMemory(child.hProcess, (void *)&stop, &value, sizeof(value), 0)) return 14;
	if (WaitForSingleObject(child.hProcess, 5000) != WAIT_OBJECT_0) return 15;
	DWORD code;
	if (!GetExitCodeProcess(child.hProcess, &code) || code) return 16;
	CloseHandle(child.hThread);
	CloseHandle(child.hProcess);
	return 0;
}

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW();
	unsigned length = 0;
	while (line[length]) ++length;
	if (!length || line[length - 1] != 'c') {
		const int result = parent();
		if (result && child.hProcess) {
			TerminateProcess(child.hProcess, 99);
			WaitForSingleObject(child.hProcess, 5000);
			CloseHandle(child.hThread);
			CloseHandle(child.hProcess);
		}
		return result;
	}
	HANDLE thread = CreateThread(0, 0, compute, 0, 0, 0);
	if (!thread) return 20;
	InterlockedIncrement(&ready);
	while (!request) InterlockedIncrement(&counters[0]);
	acknowledged = *(volatile DWORD *)remote_pointer == 0x13579bdf ? 1 : 2;
	while (!stop) InterlockedIncrement(&counters[0]);
	if (WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0) return 21;
	return counters[0] && counters[1] && acknowledged == 1 ? 0 : 22;
}

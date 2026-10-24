#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <windows.h>

typedef LONG (WINAPI *query_process)(HANDLE, ULONG, void *, ULONG, ULONG *);

struct basic_information {
	LONG exit_status;
	void *peb;
	ULONG_PTR affinity;
	LONG priority;
	ULONG_PTR pid, parent;
};

static volatile DWORD peer_id;
static volatile DWORD payload = 0x13579bdf;

static DWORD integrity(HANDLE token)
{
	union { ULONGLONG align; BYTE bytes[64]; } buffer;
	DWORD size;
	TOKEN_MANDATORY_LABEL *label = (TOKEN_MANDATORY_LABEL *)buffer.bytes;
	if (!GetTokenInformation(token, TokenIntegrityLevel, &buffer, sizeof(buffer), &size)) return 0xffffffff;
	return *GetSidSubAuthority(label->Label.Sid, 0);
}

static BOOL set_integrity(HANDLE token, DWORD level)
{
	struct { BYTE revision, count, authority[6]; DWORD level; } sid = {1, 1, {0, 0, 0, 0, 0, 16}, level};
	TOKEN_MANDATORY_LABEL label = {{&sid, SE_GROUP_INTEGRITY}};
	return SetTokenInformation(token, TokenIntegrityLevel, &label, sizeof(label));
}

static DWORD traversal(HANDLE token)
{
	TOKEN_PRIVILEGES privileges;
	DWORD size;
	if (!GetTokenInformation(token, TokenPrivileges, &privileges, sizeof(privileges), &size) || privileges.PrivilegeCount != 1)
		return 0xffffffff;
	return privileges.Privileges[0].Attributes;
}

static BOOL set_traversal(HANDLE token, DWORD attributes)
{
	TOKEN_PRIVILEGES privileges = {1, {{{23, 0}, 0}}};
	privileges.Privileges[0].Attributes = attributes;
	return AdjustTokenPrivileges(token, FALSE, &privileges, 0, NULL, NULL);
}

static BOOL start(WCHAR mode, PROCESS_INFORMATION *child)
{
	STARTUPINFOW startup = {0};
	WCHAR command[512];
	DWORD length;
	startup.cb = sizeof(startup);
	command[0] = '"';
	length = GetModuleFileNameW(NULL, command + 1, 480);
	if (!length || length >= 480) return FALSE;
	command[++length] = '"'; command[++length] = ' '; command[++length] = '-'; command[++length] = '-'; command[++length] = mode; command[++length] = 0;
	return CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, child);
}

static int query_peer(query_process query)
{
	HANDLE process, token, limited;
	struct basic_information information;
	ULONG length;
	ULONG_PTR image;
	DWORD count, value;
	SIZE_T copied;
	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, peer_id);
	if (!process || !OpenProcessToken(process, TOKEN_ALL_ACCESS, &token) || integrity(token) != 4096 || traversal(token) != 1)
		return 20;
	if (!set_integrity(token, 2048) || !set_traversal(token, SE_PRIVILEGE_ENABLED) || GetLastError() ||
		!GetProcessHandleCount(process, &count) || !count || query(process, 0, &information, sizeof(information), &length) ||
		information.pid != peer_id || !ReadProcessMemory(process, (BYTE *)information.peb + 2 * sizeof(void *), &image, sizeof(image), &copied))
		return 21;
	const void *remote = (void *)(image + (ULONG_PTR)&payload - (ULONG_PTR)GetModuleHandleW(NULL));
	if (!ReadProcessMemory(process, remote, &value, sizeof(value), &copied) || value != 0x13579bdf)
		return 22;
	value = 0x2468ace0;
	if (!WriteProcessMemory(process, (void *)remote, &value, sizeof(value), &copied) || copied != sizeof(value))
		return 23;
	limited = OpenProcess(PROCESS_VM_READ, FALSE, peer_id);
	HANDLE denied = NULL;
	if (!limited || OpenProcessToken(limited, TOKEN_QUERY, &denied) || GetLastError() != ERROR_ACCESS_DENIED || denied ||
		GetProcessHandleCount(limited, &count) || GetLastError() != ERROR_ACCESS_DENIED)
		return 24;
	CloseHandle(limited);
	CloseHandle(token);
	CloseHandle(process);
	return 0;
}

int raven_entry(void)
{
	const WCHAR *line = GetCommandLineW();
	query_process query = (query_process)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
	HANDLE token = NULL;
	for (unsigned index = 0; line[index]; ++index)
		if (line[index] == '-' && line[index + 1] == '-') {
			if (line[index + 2] == 'a') return query_peer(query);
			if (line[index + 2] == 'b') {
				if (payload != 0x2468ace0 || !OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token) || integrity(token) != 2048 || traversal(token) != 3)
					return 25;
				CloseHandle(token);
				return 0;
			}
		}
	PROCESS_INFORMATION owner, reader;
	struct basic_information information;
	ULONG length;
	ULONG_PTR image;
	SIZE_T copied;
	DWORD code = 0;
	int result = 0;
	if (!query || !start('b', &owner)) return 1;
	if (!start('a', &reader)) { TerminateProcess(owner.hProcess, 99); return 2; }
	if (!OpenProcessToken(owner.hProcess, TOKEN_ALL_ACCESS, &token) || !set_integrity(token, 4096) || !set_traversal(token, 0) ||
		query(reader.hProcess, 0, &information, sizeof(information), &length) ||
		!ReadProcessMemory(reader.hProcess, (BYTE *)information.peb + 2 * sizeof(void *), &image, sizeof(image), &copied) ||
		!WriteProcessMemory(reader.hProcess, (void *)(image + (ULONG_PTR)&peer_id - (ULONG_PTR)GetModuleHandleW(NULL)),
			&owner.dwProcessId, sizeof(owner.dwProcessId), &copied)) {
		result = 3;
		goto done;
	}
	if (ResumeThread(reader.hThread) != 1 || WaitForSingleObject(reader.hProcess, 15000) != WAIT_OBJECT_0 ||
		!GetExitCodeProcess(reader.hProcess, &code) || code || integrity(token) != 2048 || traversal(token) != 3) {
		result = code ? (int)code : 4;
		goto done;
	}
	if (ResumeThread(owner.hThread) != 1 || WaitForSingleObject(owner.hProcess, 10000) != WAIT_OBJECT_0 ||
		!GetExitCodeProcess(owner.hProcess, &code) || code || integrity(token) != 2048 || traversal(token) != 3)
		result = code ? (int)code : 5;
done:
	if (result) {
		TerminateProcess(reader.hProcess, 99);
		TerminateProcess(owner.hProcess, 99);
		WaitForSingleObject(reader.hProcess, 5000);
		WaitForSingleObject(owner.hProcess, 5000);
	}
	if (token) CloseHandle(token);
	CloseHandle(reader.hThread);
	CloseHandle(reader.hProcess);
	CloseHandle(owner.hThread);
	CloseHandle(owner.hProcess);
	return result;
}

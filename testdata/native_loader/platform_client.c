/* Host services: known folders, the computer name, network adapters, data protection, security checks and job objects. */
#define INITGUID
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <knownfolders.h>
#include <sddl.h>
#include <wincrypt.h>

static void clear(void *memory, int length)
{
	unsigned char *bytes = memory;
	int index;
	for (index = 0; index < length; ++index)
		bytes[index] = 0;
}

static int same(const void *left, const void *right, int length)
{
	const unsigned char *a = left, *b = right;
	int index;
	for (index = 0; index < length; ++index)
		if (a[index] != b[index])
			return 0;
	return 1;
}

static int contains(const WCHAR *text, const WCHAR *part)
{
	int at, index;
	for (at = 0; text[at]; ++at) {
		for (index = 0; part[index] && text[at + index] == part[index]; ++index)
			;
		if (!part[index])
			return 1;
	}
	return 0;
}

int raven_entry(void)
{
	WCHAR *folder = NULL, name[64];
	DWORD size, error;
	IP_ADAPTER_ADDRESSES *adapters, *adapter;
	ULONG needed = 0;
	DATA_BLOB plain = {5, (BYTE *)"token"}, sealed, opened, entropy = {3, (BYTE *)"abc"}, wrong = {3, (BYTE *)"xyz"};
	LPWSTR description = NULL;
	HANDLE job, token = NULL, copy = NULL;
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits, queried;
	BOOL inside = TRUE;
	DWORD mask;
	GENERIC_MAPPING mapping = {1, 2, 4, 7};
	int loopback = 0;
	PSID everyone = NULL;

	if (SHGetKnownFolderPath(&FOLDERID_RoamingAppData, 0, NULL, &folder) != S_OK || !folder || !contains(folder, L"AppData\\Roaming"))
		return 1;
	CoTaskMemFree(folder);
	if (SHGetKnownFolderPath(&FOLDERID_ProgramFilesX86, 0, NULL, &folder) != S_OK || !contains(folder, L"Program Files (x86)"))
		return 2;
	CoTaskMemFree(folder);

	size = 64;
	if (!GetComputerNameExW(ComputerNameDnsHostname, name, &size) || size == 0 || name[0] == 0)
		return 3;
	size = 1;
	if (GetComputerNameExW(ComputerNameDnsHostname, name, &size) || GetLastError() != ERROR_MORE_DATA || size < 2)
		return 4;

	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, NULL, &needed) != ERROR_BUFFER_OVERFLOW || needed < sizeof(IP_ADAPTER_ADDRESSES))
		return 5;
	adapters = HeapAlloc(GetProcessHeap(), 0, needed);
	if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, adapters, &needed) != NO_ERROR)
		return 6;
	for (adapter = adapters; adapter; adapter = adapter->Next)
		if (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK && adapter->FirstUnicastAddress && adapter->FirstUnicastAddress->Address.lpSockaddr &&
			adapter->FirstUnicastAddress->Address.iSockaddrLength >= 16)
			loopback = 1;
	if (!loopback)
		return 7;
	HeapFree(GetProcessHeap(), 0, adapters);

	if (!CryptProtectData(&plain, L"note", &entropy, NULL, NULL, 0, &sealed) || sealed.cbData <= plain.cbData)
		return 8;
	if (!CryptUnprotectData(&sealed, &description, &entropy, NULL, NULL, 0, &opened) || opened.cbData != 5 || !same(opened.pbData, "token", 5) ||
		!description || description[0] != 'n' || description[3] != 'e')
		return 9;
	LocalFree(description);
	LocalFree(opened.pbData);
	if (CryptUnprotectData(&sealed, NULL, &wrong, NULL, NULL, 0, &opened))
		return 10;
	LocalFree(sealed.pbData);

	/* Account checks: the generic rights of a mask become specific ones, and the descriptor decides the rest. */
	mask = GENERIC_READ | GENERIC_WRITE;
	MapGenericMask(&mask, &mapping);
	if (mask != 3)
		return 11;
	if (!ConvertStringSidToSidW(L"WD", &everyone))
		return 12;
	{
		SID_IDENTIFIER_AUTHORITY world = SECURITY_WORLD_SID_AUTHORITY;
		PSID expected = NULL;
		if (!AllocateAndInitializeSid(&world, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &expected) || !EqualSid(everyone, expected))
			return 13;
		FreeSid(expected);
	}
	LocalFree(everyone);

	/* Jobs keep the limits the program sets. */
	job = CreateJobObjectW(NULL, NULL);
	if (!job)
		return 14;
	clear(&limits, sizeof(limits));
	limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	limits.BasicLimitInformation.ActiveProcessLimit = 5;
	if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits)))
		return 15;
	clear(&queried, sizeof(queried));
	if (!QueryInformationJobObject(job, JobObjectExtendedLimitInformation, &queried, sizeof(queried), NULL) ||
		queried.BasicLimitInformation.ActiveProcessLimit != 5 || !(queried.BasicLimitInformation.LimitFlags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE))
		return 16;
	if (!IsProcessInJob(GetCurrentProcess(), job, &inside) || inside)
		return 17;
	CloseHandle(job);

	/* Tokens copy. */
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &token))
		return 18;
	if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenImpersonation, &copy) || !copy)
		return 19;
	CloseHandle(copy);
	CloseHandle(token);
	(void)error;
	return 0;
}

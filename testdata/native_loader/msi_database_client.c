#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>
#include <msiquery.h>

/* A Windows Installer package read as a database: its tables, its summary and a property, as setup programs read them. */

static void beside(WCHAR *target, const WCHAR *name)
{
	unsigned cut = GetModuleFileNameW(NULL, target, MAX_PATH);
	while (cut && target[cut - 1] != L'\\')
		--cut;
	for (unsigned i = 0; name[i]; ++i)
		target[cut++] = name[i];
	target[cut] = 0;
}

static BOOL same(const WCHAR *a, const WCHAR *b)
{
	while (*a && *a == *b)
		++a, ++b;
	return *a == *b;
}

int raven_entry(void)
{
	WCHAR package[MAX_PATH], text[64];
	beside(package, L"basic.msi");
	MSIHANDLE database = 0, view = 0, record = 0;
	if (MsiOpenDatabaseW(package, (LPCWSTR)MSIDBOPEN_READONLY, &database) != ERROR_SUCCESS)
		return 1;
	if (MsiDatabaseOpenViewW(database, L"SELECT `Value` FROM `Property` WHERE `Property` = 'ProductName'", &view) != ERROR_SUCCESS)
		return 2;
	if (MsiViewExecute(view, 0) != ERROR_SUCCESS || MsiViewFetch(view, &record) != ERROR_SUCCESS)
		return 3;
	DWORD size = 64;
	if (MsiRecordGetStringW(record, 1, text, &size) != ERROR_SUCCESS || !same(text, L"Raven Sample"))
		return 4;
	MsiCloseHandle(record);
	MsiViewClose(view);
	MsiCloseHandle(view);
	/* The file the package installs, from the File table. */
	if (MsiDatabaseOpenViewW(database, L"SELECT `FileName` FROM `File`", &view) != ERROR_SUCCESS || MsiViewExecute(view, 0) != ERROR_SUCCESS ||
		MsiViewFetch(view, &record) != ERROR_SUCCESS)
		return 5;
	size = 64;
	if (MsiRecordGetStringW(record, 1, text, &size) != ERROR_SUCCESS || !same(text, L"hello.txt"))
		return 6;
	MsiCloseHandle(record);
	MsiCloseHandle(view);
	/* The summary information stream names the package's platform. */
	MSIHANDLE summary = 0;
	UINT type = 0;
	INT number = 0;
	FILETIME time;
	size = 64;
	if (MsiGetSummaryInformationW(database, NULL, 0, &summary) != ERROR_SUCCESS ||
		MsiSummaryInfoGetPropertyW(summary, 7 /* PID_TEMPLATE */, &type, &number, &time, text, &size) != ERROR_SUCCESS || type != 30 /* VT_LPSTR */)
		return 7;
	MsiCloseHandle(summary);
	MsiCloseHandle(database);
	return 0;
}

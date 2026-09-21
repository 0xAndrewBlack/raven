#include <stdarg.h>
#include <windef.h>
#include <winbase.h>
#include <winerror.h>

/* What the Windows Installer component needs from libraries Raven does not ship. */

/* No compatibility database: every package runs as it is, with no shim to apply. */
BOOL WINAPI ApphelpCheckRunAppEx(HANDLE file, PVOID first, PVOID second, PCWSTR application, PVOID environment, USHORT type, PULONG reason,
	PVOID *data, PULONG data_size, PVOID *sxs, PULONG sxs_size, PULONG fusion, PULONG64 flags, PULONG more)
{
	if (reason)
		*reason = 0;
	return TRUE;
}

BOOL WINAPI SE_DynamicShim(LPCWSTR image, PVOID database, PVOID result, LPCSTR module, LPDWORD token)
{
	return FALSE;
}

PVOID WINAPI SdbInitDatabase(DWORD flags, LPCWSTR path)
{
	return NULL;
}

PVOID WINAPI SdbReleaseDatabase(PVOID database)
{
	return NULL;
}

/* Binary patches of installed files are not applied yet: a package that carries them fails that file, visibly. */
BOOL WINAPI ApplyPatchToFileW(LPCWSTR patch, LPCWSTR old, LPCWSTR target, ULONG flags)
{
	SetLastError(ERROR_CALL_NOT_IMPLEMENTED);
	return FALSE;
}

/* The script parser interface of the program's width, which script custom actions ask the engine for. */
#ifdef _WIN64
const GUID IID_IActiveScriptParse64 = {0xc7ef7658, 0xe1ee, 0x480e, {0x97, 0xea, 0xd5, 0x2c, 0xb4, 0xd7, 0x6d, 0x17}};
#else
const GUID IID_IActiveScriptParse32 = {0xbb1a2ae2, 0xa4f9, 0x11cf, {0x8f, 0x20, 0x00, 0x80, 0x5f, 0x2c, 0xd0, 0x64}};
#endif

int __cdecl wine_dbg_printf(const char *format, ...)
{
	return 0;
}

#include <windows.h>
#include <msi.h>
#include <msiquery.h>

/* Custom actions of the test package, run by the installer's custom action server: one records a package property in the registry,
   the other fails the installation so that the installer rolls back what it did. */

__declspec(dllexport) UINT __stdcall WriteMarker(MSIHANDLE install)
{
	WCHAR value[64];
	DWORD size = 64;
	HKEY key;
	if (MsiGetPropertyW(install, L"CA_VALUE", value, &size) != ERROR_SUCCESS || !size)
		return ERROR_INSTALL_FAILURE;
	if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\RavenSample", 0, NULL, 0, KEY_SET_VALUE, NULL, &key, NULL))
		return ERROR_INSTALL_FAILURE;
	RegSetValueExW(key, L"FromCustomAction", 0, REG_SZ, (const BYTE *)value, (size + 1) * sizeof(WCHAR));
	RegCloseKey(key);
	return ERROR_SUCCESS;
}

__declspec(dllexport) UINT __stdcall FailInstall(MSIHANDLE install)
{
	return ERROR_INSTALL_FAILURE;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
	return TRUE;
}

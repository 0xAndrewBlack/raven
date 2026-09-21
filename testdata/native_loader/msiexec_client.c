#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <msi.h>

/* The installer started as setup programs start it: msiexec found by name in the system directory, installing a package without a user
   interface, then removing the product by its code; a package that does not exist is refused. */

static const WCHAR product[] = L"{7B1E3C52-9A4D-4F60-8C2E-1D5A6B7C8D90}";

static DWORD run(const WCHAR *arguments, const WCHAR *package)
{
	WCHAR line[600];
	unsigned at = 0;
	for (const WCHAR *part = L"msiexec.exe "; *part; ++part)
		line[at++] = *part;
	for (; *arguments; ++arguments)
		line[at++] = *arguments;
	if (package) {
		line[at++] = L'"';
		for (; *package; ++package)
			line[at++] = *package;
		line[at++] = L'"';
	}
	for (const WCHAR *part = L" /qn"; *part; ++part)
		line[at++] = *part;
	line[at] = 0;
	STARTUPINFOW startup = {sizeof startup};
	PROCESS_INFORMATION process;
	if (!CreateProcessW(NULL, line, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process))
		return 0xffffffff;
	DWORD code = 0xfffffffe;
	WaitForSingleObject(process.hProcess, 120000);
	GetExitCodeProcess(process.hProcess, &code);
	CloseHandle(process.hThread);
	CloseHandle(process.hProcess);
	return code;
}

int raven_entry(void)
{
	WCHAR package[MAX_PATH];
	unsigned cut = GetModuleFileNameW(NULL, package, MAX_PATH);
	while (cut && package[cut - 1] != L'\\')
		--cut;
	const WCHAR name[] = L"basic.msi";
	for (unsigned i = 0; name[i]; ++i)
		package[cut++] = name[i];
	package[cut] = 0;
	if (MsiQueryProductStateW(product) == INSTALLSTATE_DEFAULT && run(L"/x ", product))
		return 1;
	DWORD code = run(L"/i ", package);
	if (code)
		return 10 + (int)(code % 1000);
	if (MsiQueryProductStateW(product) != INSTALLSTATE_DEFAULT)
		return 2;
	code = run(L"/x ", product);
	if (code)
		return 2000 + (int)(code % 1000);
	if (MsiQueryProductStateW(product) != INSTALLSTATE_UNKNOWN)
		return 3;
	/* MsiInstallProduct answers a missing file with ERROR_FILE_NOT_FOUND; msiexec on Windows is documented to end with
	   ERROR_INSTALL_PACKAGE_OPEN_FAILED. Either refuses the package. */
	package[cut - 9] = L'X';
	code = run(L"/i ", package);
	if (code != ERROR_INSTALL_PACKAGE_OPEN_FAILED && code != ERROR_FILE_NOT_FOUND)
		return 4;
	return 0;
}

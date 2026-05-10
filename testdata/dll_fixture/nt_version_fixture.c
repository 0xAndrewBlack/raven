#include <windows.h>

typedef VOID (WINAPI *rtl_get_nt_version_numbers_fn)(LPDWORD, LPDWORD, LPDWORD);

void raven_entry(void) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    rtl_get_nt_version_numbers_fn get_version;
    DWORD major = 0;
    DWORD minor = 0;
    DWORD build = 0;

    if (!ntdll) {
        ExitProcess(10);
    }
    get_version = (rtl_get_nt_version_numbers_fn)GetProcAddress(
        ntdll, "RtlGetNtVersionNumbers");
    if (!get_version) {
        ExitProcess(11);
    }
    if (GetProcAddress(ntdll, "wine_get_version")) {
        ExitProcess(12);
    }

    get_version(&major, &minor, &build);
    if (major != 10 || minor != 0 || (build & 0xFFFF) != 19045 ||
        (build & 0xF0000000) != 0xF0000000) {
        ExitProcess(13);
    }

    minor = 99;
    get_version(NULL, &minor, NULL);
    if (minor != 0) {
        ExitProcess(14);
    }
    ExitProcess(0);
}

#ifdef _WIN64
#define WINAPI
#define CDECL
#else
#define WINAPI __attribute__((stdcall))
#define CDECL __attribute__((cdecl))
#endif

#define DLLIMPORT __declspec(dllimport)

typedef unsigned int UINT;
typedef unsigned short WCHAR;
typedef void *HMODULE;
typedef void *FARPROC;
typedef WCHAR **(CDECL *WCMD_PROC)(void);
typedef WCHAR ***(CDECL *WARGV_PROC)(void);
typedef __SIZE_TYPE__ (CDECL *WCSLEN_PROC)(const WCHAR *);

DLLIMPORT WCHAR *WINAPI GetCommandLineW(void);
DLLIMPORT void WINAPI ExitProcess(UINT);
DLLIMPORT HMODULE WINAPI LoadLibraryW(const WCHAR *);
DLLIMPORT FARPROC WINAPI GetProcAddress(HMODULE, const char *);

static const WCHAR expected[] = {
    'u','n','i','c','o','d','e','-',0xd83d,0xde00,'-',
    0x65e5,0x672c,0x8a9e,'.','m','d',0
};
static const WCHAR msvcrt_name[] = {
    'm','s','v','c','r','t','.','d','l','l',0
};
static const WCHAR ucrtbase_name[] = {
    'u','c','r','t','b','a','s','e','.','d','l','l',0
};

static int contains(const WCHAR *text, const WCHAR *needle) {
    const WCHAR *start;
    const WCHAR *left;
    const WCHAR *right;

    for (start = text; *start; start++) {
        left = start;
        right = needle;
        while (*right && *left == *right) {
            left++;
            right++;
        }
        if (!*right) {
            return 1;
        }
    }
    return 0;
}

void raven_entry(void) {
    WCHAR *command_line = GetCommandLineW();
    HMODULE msvcrt = LoadLibraryW(msvcrt_name);
    HMODULE ucrtbase = LoadLibraryW(ucrtbase_name);
    WCMD_PROC get_wcmd = (WCMD_PROC)GetProcAddress(msvcrt, "__p__wcmdln");
    WARGV_PROC get_msvcrt_wargv =
        (WARGV_PROC)GetProcAddress(msvcrt, "__p___wargv");
    WARGV_PROC get_ucrt_wargv =
        (WARGV_PROC)GetProcAddress(ucrtbase, "__p___wargv");
    WCSLEN_PROC msvcrt_wcslen =
        (WCSLEN_PROC)GetProcAddress(msvcrt, "wcslen");
    WCSLEN_PROC ucrt_wcslen =
        (WCSLEN_PROC)GetProcAddress(ucrtbase, "wcslen");
    WCHAR **wide_command_line;
    WCHAR ***msvcrt_wargv;
    WCHAR ***ucrt_wargv;

    if (!command_line || !contains(command_line, expected)) {
        ExitProcess(1);
    }
    if (!get_wcmd || !get_msvcrt_wargv || !get_ucrt_wargv ||
        !msvcrt_wcslen || !ucrt_wcslen) {
        ExitProcess(2);
    }
    if (msvcrt_wcslen(expected) != 17) {
        ExitProcess(6);
    }
    if (ucrt_wcslen(expected) != 17) {
        ExitProcess(7);
    }
    wide_command_line = get_wcmd();
    msvcrt_wargv = get_msvcrt_wargv();
    ucrt_wargv = get_ucrt_wargv();
    if (!wide_command_line || !*wide_command_line ||
        !contains(*wide_command_line, expected)) {
        ExitProcess(3);
    }
    if (!msvcrt_wargv || !*msvcrt_wargv || !(*msvcrt_wargv)[1] ||
        !contains((*msvcrt_wargv)[1], expected)) {
        ExitProcess(4);
    }
    if (!ucrt_wargv || !*ucrt_wargv || !(*ucrt_wargv)[1] ||
        !contains((*ucrt_wargv)[1], expected)) {
        ExitProcess(5);
    }
    ExitProcess(0);
}

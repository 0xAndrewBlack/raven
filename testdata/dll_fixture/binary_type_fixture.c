#ifdef _WIN64
#define WINAPI
#else
#define WINAPI __attribute__((stdcall))
#endif

#define DLLIMPORT __declspec(dllimport)

typedef int BOOL;
typedef unsigned int UINT;
typedef unsigned long DWORD;

DLLIMPORT DWORD WINAPI GetModuleFileNameW(void *, unsigned short *, DWORD);
DLLIMPORT BOOL WINAPI GetBinaryTypeW(const unsigned short *, DWORD *);
DLLIMPORT DWORD WINAPI GetLastError(void);
DLLIMPORT void WINAPI SetLastError(DWORD);
DLLIMPORT void WINAPI ExitProcess(UINT);

#define SCS_32BIT_BINARY 0
#define SCS_64BIT_BINARY 6
#define ERROR_BAD_EXE_FORMAT 193

#ifdef _WIN64
static const unsigned short sibling_name[] = L"binary-type-64.dll";
#else
static const unsigned short sibling_name[] = L"binary-type-32.dll";
#endif

void raven_entry(void) {
    unsigned short path[512];
    DWORD binary_type = 0xffffffff;
    DWORD length;
    DWORD name_start = 0;
    DWORD i;

    length = GetModuleFileNameW(0, path, 512);
    if (length == 0 || length >= 512) {
        ExitProcess(10);
    }
    if (!GetBinaryTypeW(path, &binary_type)) {
        ExitProcess(11);
    }
#ifdef _WIN64
    if (binary_type != SCS_64BIT_BINARY) {
        ExitProcess(12);
    }
#else
    if (binary_type != SCS_32BIT_BINARY) {
        ExitProcess(13);
    }
#endif

    for (i = 0; i < length; i++) {
        if (path[i] == L'\\' || path[i] == L'/') {
            name_start = i + 1;
        }
    }
    for (i = 0; sibling_name[i] != 0; i++) {
        if (name_start + i + 1 >= 512) {
            ExitProcess(14);
        }
        path[name_start + i] = sibling_name[i];
    }
    path[name_start + i] = 0;

    SetLastError(0);
    binary_type = 0xffffffff;
    if (GetBinaryTypeW(path, &binary_type)) {
        ExitProcess(15);
    }
    if (GetLastError() != ERROR_BAD_EXE_FORMAT) {
        ExitProcess(16);
    }
    ExitProcess(0);
}

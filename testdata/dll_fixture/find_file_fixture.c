#ifdef _WIN64
#define WINAPI
#else
#define WINAPI __attribute__((stdcall))
#endif

#define DLLIMPORT __declspec(dllimport)
#define NULL ((void *)0)

typedef int BOOL;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef unsigned short WCHAR;
#ifdef _WIN64
typedef unsigned long long UINT_PTR;
#else
typedef unsigned long UINT_PTR;
#endif
typedef void *HANDLE;
typedef DWORD (WINAPI *THREAD_START_ROUTINE)(void *);

typedef struct {
    DWORD low;
    DWORD high;
} FILETIME;

typedef struct {
    DWORD attributes;
    FILETIME creation_time;
    FILETIME last_access_time;
    FILETIME last_write_time;
    DWORD size_high;
    DWORD size_low;
    DWORD reserved0;
    DWORD reserved1;
    WCHAR file_name[260];
    WCHAR alternate_file_name[14];
} WIN32_FIND_DATAW;

typedef struct {
    DWORD attributes;
    FILETIME creation_time;
    FILETIME last_access_time;
    FILETIME last_write_time;
    DWORD size_high;
    DWORD size_low;
    DWORD reserved0;
    DWORD reserved1;
    char file_name[260];
    char alternate_file_name[14];
} WIN32_FIND_DATAA;

DLLIMPORT HANDLE WINAPI CreateThread(
    void *, UINT_PTR, THREAD_START_ROUTINE, void *, DWORD, DWORD *
);
DLLIMPORT HANDLE WINAPI CreateFileW(
    const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE
);
DLLIMPORT WCHAR *WINAPI GetCommandLineW(void);
DLLIMPORT DWORD WINAPI GetLastError(void);
DLLIMPORT void WINAPI SetLastError(DWORD);
DLLIMPORT BOOL WINAPI GetModuleHandleExW(DWORD, const WCHAR *, HANDLE *);
DLLIMPORT DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE);
DLLIMPORT HANDLE WINAPI FindFirstFileW(const WCHAR *, WIN32_FIND_DATAW *);
DLLIMPORT HANDLE WINAPI FindFirstFileExW(
    const WCHAR *, int, WIN32_FIND_DATAW *, int, void *, DWORD
);
DLLIMPORT HANDLE WINAPI FindFirstFileExA(
    const char *, int, WIN32_FIND_DATAA *, int, void *, DWORD
);
DLLIMPORT BOOL WINAPI FindNextFileW(HANDLE, WIN32_FIND_DATAW *);
DLLIMPORT BOOL WINAPI FindNextFileA(HANDLE, WIN32_FIND_DATAA *);
DLLIMPORT BOOL WINAPI FindClose(HANDLE);
DLLIMPORT void WINAPI ExitProcess(UINT);

#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define INFINITE 0xffffffffUL
#define WAIT_OBJECT_0 0
#define GENERIC_WRITE 0x40000000UL
#define CREATE_ALWAYS 2
#define FILE_ATTRIBUTE_DIRECTORY 0x10
#define ERROR_FILE_NOT_FOUND 2
#define ERROR_PATH_NOT_FOUND 3
#define ERROR_INVALID_HANDLE 6
#define ERROR_NO_MORE_FILES 18
#define ERROR_MOD_NOT_FOUND 126

static const WCHAR marker_name[] = {
    'f','i','n','d','_','f','i','l','e','_','f','i','x','t','u','r','e',
    '_','m','a','r','k','e','r','.','t','x','t',0
};
static const WCHAR missing_name[] = {
    'f','i','n','d','_','f','i','l','e','_','m','i','s','s','i','n','g',
    '.','t','x','t',0
};
static const WCHAR uppercase_marker_name[] = {
    'F','I','N','D','_','F','I','L','E','_','F','I','X','T','U','R','E',
    '_','M','A','R','K','E','R','.','T','X','T',0
};
static const WCHAR missing_dir[] = {
    'm','i','s','s','i','n','g','_','d','i','r','e','c','t','o','r','y',
    '\\','*','.','t','x','t',0
};
static const WCHAR missing_module[] = {
    'r','a','v','e','n','_','m','i','s','s','i','n','g','.','d','l','l',0
};
static const WCHAR vfs_pattern[] = {
    'C',':','\\','W','i','n','d','o','w','s','\\','T','e','m','p','\\',
    '*','.','r','v','n','x','m','l',0
};
static const WCHAR vfs_marker[] = {
    'C',':','\\','W','i','n','d','o','w','s','\\','T','e','m','p','\\',
    'r','a','v','e','n','_','v','f','s','_','f','i','n','d','.',
    'r','v','n','x','m','l',0
};
static const char vfs_pattern_a[] =
    "C:\\Windows\\Temp\\*.rvnxml";
static const char vfs_marker_name_a[] =
    "raven_vfs_find.rvnxml";

static volatile DWORD worker_error;

static int wide_equal(const WCHAR *left, const WCHAR *right) {
    while (*left && *right && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static int ansi_equal(const char *left, const char *right) {
    while (*left && *right && *left == *right) {
        left++;
        right++;
    }
    return *left == *right;
}

static BOOL replace_file_name(WCHAR *path, DWORD capacity, const WCHAR *name) {
    DWORD end = 0;
    DWORD base = 0;
    DWORD i = 0;

    while (end < capacity && path[end]) {
        if (path[end] == '\\' || path[end] == '/') {
            base = end + 1;
        }
        end++;
    }
    while (name[i]) {
        if (base + i + 1 >= capacity) {
            return 0;
        }
        path[base + i] = name[i];
        i++;
    }
    path[base + i] = 0;
    return 1;
}

static BOOL read_marker_path(WCHAR *path, DWORD capacity) {
    const WCHAR *command_line = GetCommandLineW();
    DWORD output = 0;

    if (*command_line == '"') {
        command_line++;
        while (*command_line && *command_line != '"') {
            command_line++;
        }
        if (*command_line == '"') {
            command_line++;
        }
    } else {
        while (*command_line && *command_line != ' ') {
            command_line++;
        }
    }
    while (*command_line == ' ') {
        command_line++;
    }
    if (*command_line == '"') {
        command_line++;
        while (*command_line && *command_line != '"' && output + 1 < capacity) {
            path[output++] = *command_line++;
        }
    } else {
        while (*command_line && *command_line != ' ' && output + 1 < capacity) {
            path[output++] = *command_line++;
        }
    }
    path[output] = 0;
    return output != 0;
}

static DWORD WINAPI worker_main(void *unused) {
    WIN32_FIND_DATAW data;
    (void)unused;
    SetLastError(222);
    if (FindNextFileW(INVALID_HANDLE_VALUE, &data) ||
        GetLastError() != ERROR_INVALID_HANDLE) {
        worker_error = 223;
        return 1;
    }
    worker_error = GetLastError();
    return 0;
}

void raven_entry(void) {
    WCHAR path[520];
    WIN32_FIND_DATAW data;
    WIN32_FIND_DATAA data_a;
    HANDLE find;
    HANDLE file;
    HANDLE module;
    HANDLE worker;
    DWORD count;
    DWORD tid;

    SetLastError(111);
    worker = CreateThread(NULL, 0, worker_main, NULL, 0, &tid);
    if (!worker ||
        WaitForSingleObject(worker, INFINITE) != WAIT_OBJECT_0 ||
        worker_error != ERROR_INVALID_HANDLE ||
        GetLastError() != 111) {
        ExitProcess(10);
    }
    CloseHandle(worker);

    if (!read_marker_path(path, 520)) {
        ExitProcess(11);
    }
    find = FindFirstFileW(path, &data);
    if (find == INVALID_HANDLE_VALUE ||
        !wide_equal(data.file_name, marker_name) ||
        (data.attributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
        ExitProcess(12);
    }
    SetLastError(77);
    if (FindNextFileW(find, &data) ||
        GetLastError() != ERROR_NO_MORE_FILES ||
        !FindClose(find)) {
        ExitProcess(13);
    }

    find = FindFirstFileExW(path, 0, &data, 0, NULL, 0);
    if (find == INVALID_HANDLE_VALUE ||
        !wide_equal(data.file_name, marker_name) ||
        !FindClose(find)) {
        ExitProcess(14);
    }

    if (!replace_file_name(path, 520, uppercase_marker_name)) {
        ExitProcess(15);
    }
    find = FindFirstFileW(path, &data);
    if (find == INVALID_HANDLE_VALUE ||
        !wide_equal(data.file_name, marker_name) ||
        !FindClose(find)) {
        ExitProcess(16);
    }

    if (!replace_file_name(path, 520, missing_name)) {
        ExitProcess(17);
    }
    SetLastError(77);
    if (FindFirstFileW(path, &data) != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_FILE_NOT_FOUND) {
        ExitProcess(18);
    }

    if (!replace_file_name(path, 520, missing_dir)) {
        ExitProcess(19);
    }
    SetLastError(77);
    if (FindFirstFileW(path, &data) != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_PATH_NOT_FOUND) {
        ExitProcess(20);
    }

    SetLastError(77);
    if (FindNextFileW(INVALID_HANDLE_VALUE, &data) ||
        GetLastError() != ERROR_INVALID_HANDLE) {
        ExitProcess(21);
    }
    SetLastError(77);
    if (GetModuleHandleExW(0, missing_module, &module) ||
        GetLastError() != ERROR_MOD_NOT_FOUND) {
        ExitProcess(22);
    }

    file = CreateFileW(vfs_marker, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    SetLastError(77);
    if (file == INVALID_HANDLE_VALUE ||
        FindClose(file) ||
        GetLastError() != ERROR_INVALID_HANDLE ||
        !CloseHandle(file)) {
        ExitProcess(23);
    }

    find = FindFirstFileW(vfs_pattern, &data);
    if (find == INVALID_HANDLE_VALUE) {
        ExitProcess(24);
    }
    count = 1;
    while (FindNextFileW(find, &data)) {
        count++;
    }
    if (count != 1 || GetLastError() != ERROR_NO_MORE_FILES ||
        !FindClose(find)) {
        ExitProcess(25);
    }

    find = FindFirstFileExA(vfs_pattern_a, 0, &data_a, 0, NULL, 0);
    if (find == INVALID_HANDLE_VALUE ||
        !ansi_equal(data_a.file_name, vfs_marker_name_a)) {
        ExitProcess(26);
    }
    count = 1;
    while (FindNextFileA(find, &data_a)) {
        count++;
    }
    if (count != 1 || GetLastError() != ERROR_NO_MORE_FILES ||
        !FindClose(find)) {
        ExitProcess(27);
    }
    ExitProcess(0);
}

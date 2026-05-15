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
typedef unsigned long long ULONG_PTR;
#else
typedef unsigned long ULONG_PTR;
#endif
typedef void *HANDLE;
typedef DWORD (WINAPI *THREAD_START_ROUTINE)(void *);

typedef struct {
    ULONG_PTR internal;
    ULONG_PTR internal_high;
    union {
        struct {
            DWORD offset;
            DWORD offset_high;
        };
        void *pointer;
    };
    HANDLE event;
} OVERLAPPED;

typedef struct {
    DWORD next_entry_offset;
    DWORD action;
    DWORD file_name_length;
    WCHAR file_name[1];
} FILE_NOTIFY_INFORMATION;

typedef void (WINAPI *OVERLAPPED_COMPLETION_ROUTINE)(
    DWORD, DWORD, OVERLAPPED *
);

DLLIMPORT HANDLE WINAPI CreateEventW(void *, BOOL, BOOL, const WCHAR *);
DLLIMPORT BOOL WINAPI SetEvent(HANDLE);
DLLIMPORT HANDLE WINAPI CreateThread(
    void *, ULONG_PTR, THREAD_START_ROUTINE, void *, DWORD, DWORD *
);
DLLIMPORT HANDLE WINAPI CreateFileW(
    const WCHAR *, DWORD, DWORD, void *, DWORD, DWORD, HANDLE
);
DLLIMPORT BOOL WINAPI WriteFile(
    HANDLE, const void *, DWORD, DWORD *, OVERLAPPED *
);
DLLIMPORT BOOL WINAPI ReadDirectoryChangesW(
    HANDLE, void *, DWORD, BOOL, DWORD, DWORD *, OVERLAPPED *,
    OVERLAPPED_COMPLETION_ROUTINE
);
DLLIMPORT BOOL WINAPI GetOverlappedResult(
    HANDLE, OVERLAPPED *, DWORD *, BOOL
);
DLLIMPORT BOOL WINAPI GetOverlappedResultEx(
    HANDLE, OVERLAPPED *, DWORD *, DWORD, BOOL
);
DLLIMPORT HANDLE WINAPI CreateIoCompletionPort(
    HANDLE, HANDLE, ULONG_PTR, DWORD
);
DLLIMPORT BOOL WINAPI GetQueuedCompletionStatus(
    HANDLE, DWORD *, ULONG_PTR *, OVERLAPPED **, DWORD
);
DLLIMPORT BOOL WINAPI CancelIoEx(HANDLE, OVERLAPPED *);
DLLIMPORT DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
DLLIMPORT DWORD WINAPI SleepEx(DWORD, BOOL);
DLLIMPORT DWORD WINAPI GetLastError(void);
DLLIMPORT void WINAPI SetLastError(DWORD);
DLLIMPORT WCHAR *WINAPI GetCommandLineW(void);
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE);
DLLIMPORT BOOL WINAPI DuplicateHandle(
    HANDLE, HANDLE, HANDLE, HANDLE *, DWORD, BOOL, DWORD
);
DLLIMPORT void WINAPI ExitProcess(UINT);

#define FALSE 0
#define TRUE 1
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define INFINITE 0xffffffffUL
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 0x102
#define WAIT_IO_COMPLETION 0xc0
#define FILE_LIST_DIRECTORY 0x0001
#define GENERIC_WRITE 0x40000000UL
#define FILE_SHARE_READ 0x00000001
#define FILE_SHARE_WRITE 0x00000002
#define FILE_SHARE_DELETE 0x00000004
#define CREATE_ALWAYS 2
#define OPEN_EXISTING 3
#define FILE_ATTRIBUTE_NORMAL 0x00000080
#define FILE_FLAG_BACKUP_SEMANTICS 0x02000000
#define FILE_FLAG_OVERLAPPED 0x40000000
#define FILE_NOTIFY_CHANGE_FILE_NAME 0x00000001
#define FILE_NOTIFY_CHANGE_SIZE 0x00000008
#define FILE_NOTIFY_CHANGE_LAST_WRITE 0x00000010
#define FILE_ACTION_ADDED 0x00000001
#define FILE_ACTION_MODIFIED 0x00000003
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_PARAMETER 87
#define ERROR_OPERATION_ABORTED 995
#define ERROR_IO_INCOMPLETE 996
#define DUPLICATE_SAME_ACCESS 0x00000002
#ifdef _WIN64
#define COMPLETION_KEY ((ULONG_PTR)0x1122334455667788ULL)
#else
#define COMPLETION_KEY ((ULONG_PTR)0x55667788UL)
#endif

#define FAILURE_IOCP 0x01
#define FAILURE_RESULT_EX 0x02
#define FAILURE_APC 0x04
#define FAILURE_OVERFLOW 0x08
#define FAILURE_INVALID 0x10
#define FAILURE_REARM 0x20

static const WCHAR change_name[] = {
    'o','v','e','r','l','a','p','p','e','d','-','c','h','a','n','g','e',
    '.','t','x','t',0
};
static const WCHAR rearm_first_name[] = {
    'r','e','a','r','m','-','f','i','r','s','t','.','t','x','t',0
};
static const WCHAR rearm_queued_name[] = {
    'r','e','a','r','m','-','b','e','f','o','r','e','-','n','e','x','t',
    '.','t','x','t',0
};
static const WCHAR overflow_name[] = {
    'o','v','e','r','f','l','o','w','-','n','o','t','i','f','i','c','a',
    't','i','o','n','-','n','a','m','e','-','t','h','a','t','-','d','o',
    'e','s','-','n','o','t','-','f','i','t','.','t','x','t',0
};
static const WCHAR iocp_name[] = {
    'i','o','c','p','-','c','h','a','n','g','e','.','t','x','t',0
};
static const WCHAR low_bit_name[] = {
    'l','o','w','-','b','i','t','-','e','v','e','n','t','.','t','x','t',0
};
static const WCHAR result_ex_name[] = {
    'r','e','s','u','l','t','-','e','x','.','t','x','t',0
};
static const WCHAR apc_name[] = {
    'a','p','c','-','c','o','m','p','l','e','t','i','o','n','.','t','x','t',0
};
static WCHAR change_path[520];
static HANDLE worker_start;
static volatile DWORD worker_result;
static volatile DWORD apc_called;
static volatile DWORD apc_error;
static volatile DWORD apc_bytes;
static OVERLAPPED *volatile apc_overlapped;

static BOOL read_directory_path(WCHAR *path, DWORD capacity) {
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

static BOOL build_change_path(
    const WCHAR *directory,
    const WCHAR *name,
    WCHAR *path,
    DWORD capacity
) {
    DWORD output = 0;
    DWORD name_offset = 0;

    while (directory[output] && output + 1 < capacity) {
        path[output] = directory[output];
        output++;
    }
    if (directory[output] || output + 2 >= capacity) {
        return FALSE;
    }
    if (output && path[output - 1] != '/' &&
        path[output - 1] != '\\') {
        path[output++] = '/';
    }
    while (name[name_offset] && output + 1 < capacity) {
        path[output++] = name[name_offset++];
    }
    if (name[name_offset]) {
        return FALSE;
    }
    path[output] = 0;
    return TRUE;
}

static BOOL notification_matches(
    const unsigned char *buffer,
    DWORD bytes,
    DWORD capacity,
    const WCHAR *expected_name
) {
    DWORD offset = 0;
    BOOL found = FALSE;

    if (bytes < 12 || bytes > capacity) {
        return FALSE;
    }
    for (;;) {
        const FILE_NOTIFY_INFORMATION *notification;
        DWORD index;
        DWORD name_chars;
        DWORD record_size;
        DWORD remaining = bytes - offset;

        if (remaining < 12) {
            return FALSE;
        }
        notification = (const FILE_NOTIFY_INFORMATION *)(buffer + offset);
        if (!notification->file_name_length ||
            notification->file_name_length > remaining - 12 ||
            (notification->file_name_length & 1) != 0 ||
            notification->action < 1 ||
            notification->action > 5) {
            return FALSE;
        }
        record_size = 12 + notification->file_name_length;
        if (notification->next_entry_offset) {
            if ((notification->next_entry_offset & 3) != 0 ||
                notification->next_entry_offset < record_size ||
                notification->next_entry_offset > remaining) {
                return FALSE;
            }
        } else if (remaining - record_size > 3) {
            return FALSE;
        }
        name_chars = notification->file_name_length / sizeof(WCHAR);
        for (index = 0; index < name_chars && expected_name[index]; index++) {
            if (notification->file_name[index] != expected_name[index]) {
                break;
            }
        }
        if (index == name_chars &&
            expected_name[index] == 0 &&
            (notification->action == FILE_ACTION_ADDED ||
             notification->action == FILE_ACTION_MODIFIED)) {
            found = TRUE;
        }
        if (!notification->next_entry_offset) {
            return found;
        }
        offset += notification->next_entry_offset;
    }
}

static void init_overlapped(OVERLAPPED *overlapped, HANDLE event) {
    overlapped->internal = 0;
    overlapped->internal_high = 0;
    overlapped->offset = 0;
    overlapped->offset_high = 0;
    overlapped->event = event;
}

static HANDLE open_directory(
    const WCHAR *path,
    DWORD access,
    DWORD flags
) {
    return CreateFileW(
        path,
        access,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        flags,
        NULL
    );
}

static BOOL create_named_file(
    const WCHAR *directory,
    const WCHAR *name
) {
    static const char contents[] = "changed";
    WCHAR path[520];
    HANDLE file;
    DWORD written = 0;

    if (!build_change_path(directory, name, path, 520)) {
        return FALSE;
    }
    file = CreateFileW(
        path,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!WriteFile(file, contents, sizeof(contents) - 1, &written, NULL) ||
        written != sizeof(contents) - 1) {
        CloseHandle(file);
        return FALSE;
    }
    return CloseHandle(file);
}

static BOOL arm_directory_read(
    HANDLE directory,
    void *buffer,
    DWORD buffer_size,
    DWORD filter,
    OVERLAPPED *overlapped,
    OVERLAPPED_COMPLETION_ROUTINE completion
) {
    return ReadDirectoryChangesW(
        directory,
        buffer,
        buffer_size,
        FALSE,
        filter,
        NULL,
        overlapped,
        completion
    );
}

static DWORD WINAPI worker_main(void *unused) {
    static const char contents[] = "changed";
    HANDLE file;
    DWORD written = 0;
    (void)unused;

    if (WaitForSingleObject(worker_start, INFINITE) != WAIT_OBJECT_0) {
        worker_result = 1;
        return 1;
    }
    file = CreateFileW(
        change_path,
        GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (file == INVALID_HANDLE_VALUE) {
        worker_result = 2;
        return 2;
    }
    if (!WriteFile(file, contents, sizeof(contents) - 1, &written, NULL) ||
        written != sizeof(contents) - 1) {
        CloseHandle(file);
        worker_result = 3;
        return 3;
    }
    if (!CloseHandle(file)) {
        worker_result = 4;
        return 4;
    }
    worker_result = 5;
    return 0;
}

static void WINAPI directory_completion(
    DWORD error,
    DWORD bytes,
    OVERLAPPED *overlapped
) {
    apc_error = error;
    apc_bytes = bytes;
    apc_overlapped = overlapped;
    apc_called = 1;
}

static BOOL test_iocp(const WCHAR *directory_path) {
    union {
        ULONG_PTR alignment;
        unsigned char bytes[1024];
    } buffer, low_bit_buffer;
    OVERLAPPED overlapped;
    OVERLAPPED low_bit_overlapped;
    OVERLAPPED *completed = NULL;
    HANDLE directory = INVALID_HANDLE_VALUE;
    HANDLE duplicate_directory = NULL;
    HANDLE port = NULL;
    HANDLE duplicate_port = NULL;
    HANDLE event = NULL;
    HANDLE low_bit_event = NULL;
    DWORD transferred = 0;
    ULONG_PTR key = 0;
    BOOL ok = FALSE;

    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    if (directory == INVALID_HANDLE_VALUE) {
        goto done;
    }
    port = CreateIoCompletionPort(directory, NULL, COMPLETION_KEY, 0);
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    low_bit_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!port || !event || !low_bit_event) {
        goto done;
    }
    if (!DuplicateHandle(
            INVALID_HANDLE_VALUE,
            directory,
            INVALID_HANDLE_VALUE,
            &duplicate_directory,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        ) ||
        !DuplicateHandle(
            INVALID_HANDLE_VALUE,
            port,
            INVALID_HANDLE_VALUE,
            &duplicate_port,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS
        ) ||
        !CloseHandle(directory) ||
        !CloseHandle(port)) {
        goto done;
    }
    directory = duplicate_directory;
    duplicate_directory = NULL;
    port = duplicate_port;
    duplicate_port = NULL;
    init_overlapped(&overlapped, event);
    if (!arm_directory_read(
            directory,
            buffer.bytes,
            sizeof(buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            &overlapped,
            NULL
        ) ||
        !create_named_file(directory_path, iocp_name)) {
        goto done;
    }
    if (!GetQueuedCompletionStatus(
            port,
            &transferred,
            &key,
            &completed,
            2000
        ) ||
        key != COMPLETION_KEY ||
        completed != &overlapped ||
        !notification_matches(
            buffer.bytes,
            transferred,
            sizeof(buffer.bytes),
            iocp_name
        ) ||
        WaitForSingleObject(event, 0) != WAIT_OBJECT_0) {
        goto done;
    }

    if (!CloseHandle(directory) || !CloseHandle(port)) {
        goto done;
    }
    directory = INVALID_HANDLE_VALUE;
    port = NULL;
    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    if (directory == INVALID_HANDLE_VALUE) {
        goto done;
    }
    port = CreateIoCompletionPort(directory, NULL, COMPLETION_KEY, 0);
    if (!port) {
        goto done;
    }
    init_overlapped(
        &low_bit_overlapped,
        (HANDLE)((ULONG_PTR)low_bit_event | 1)
    );
    if (!arm_directory_read(
            directory,
            low_bit_buffer.bytes,
            sizeof(low_bit_buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            &low_bit_overlapped,
            NULL
        ) ||
        !create_named_file(directory_path, low_bit_name) ||
        WaitForSingleObject(low_bit_event, 2000) != WAIT_OBJECT_0 ||
        !GetOverlappedResult(
            directory,
            &low_bit_overlapped,
            &transferred,
            FALSE
        ) ||
        !notification_matches(
            low_bit_buffer.bytes,
            transferred,
            sizeof(low_bit_buffer.bytes),
            low_bit_name
        ) ||
        WaitForSingleObject(low_bit_event, 0) != WAIT_OBJECT_0) {
        goto done;
    }
    SetLastError(0);
    if (GetQueuedCompletionStatus(
            port,
            &transferred,
            &key,
            &completed,
            0
        ) ||
        GetLastError() != WAIT_TIMEOUT) {
        goto done;
    }
    ok = TRUE;

done:
    if (directory != INVALID_HANDLE_VALUE) {
        CloseHandle(directory);
    }
    if (port) {
        CloseHandle(port);
    }
    if (duplicate_directory) {
        CloseHandle(duplicate_directory);
    }
    if (duplicate_port) {
        CloseHandle(duplicate_port);
    }
    if (event) {
        CloseHandle(event);
    }
    if (low_bit_event) {
        CloseHandle(low_bit_event);
    }
    return ok;
}

static BOOL test_result_ex(const WCHAR *directory_path) {
    union {
        ULONG_PTR alignment;
        unsigned char bytes[1024];
    } buffer;
    OVERLAPPED overlapped;
    HANDLE directory = INVALID_HANDLE_VALUE;
    HANDLE event = NULL;
    DWORD transferred = 0;
    BOOL ok = FALSE;

    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (directory == INVALID_HANDLE_VALUE || !event) {
        goto done;
    }
    init_overlapped(&overlapped, event);
    if (!arm_directory_read(
            directory,
            buffer.bytes,
            sizeof(buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            &overlapped,
            NULL
        )) {
        goto done;
    }
    SetLastError(0);
    if (GetOverlappedResultEx(
            directory,
            &overlapped,
            &transferred,
            1,
            FALSE
        ) ||
        GetLastError() != WAIT_TIMEOUT ||
        WaitForSingleObject(event, 0) != WAIT_TIMEOUT ||
        !create_named_file(directory_path, result_ex_name) ||
        !GetOverlappedResultEx(
            directory,
            &overlapped,
            &transferred,
            2000,
            FALSE
        ) ||
        !notification_matches(
            buffer.bytes,
            transferred,
            sizeof(buffer.bytes),
            result_ex_name
        ) ||
        WaitForSingleObject(event, 0) != WAIT_OBJECT_0) {
        goto done;
    }
    ok = TRUE;

done:
    if (directory != INVALID_HANDLE_VALUE) {
        CloseHandle(directory);
    }
    if (event) {
        CloseHandle(event);
    }
    return ok;
}

static BOOL test_apc(const WCHAR *directory_path) {
    union {
        ULONG_PTR alignment;
        unsigned char bytes[1024];
    } buffer;
    OVERLAPPED overlapped;
    HANDLE directory = INVALID_HANDLE_VALUE;
    DWORD wait_result;
    BOOL ok = FALSE;

    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    if (directory == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    init_overlapped(&overlapped, NULL);
    apc_called = 0;
    apc_error = 0xffffffffUL;
    apc_bytes = 0;
    apc_overlapped = NULL;
    if (!arm_directory_read(
            directory,
            buffer.bytes,
            sizeof(buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            &overlapped,
            directory_completion
        ) ||
        !create_named_file(directory_path, apc_name)) {
        goto done;
    }
    wait_result = SleepEx(2000, TRUE);
    if (wait_result != WAIT_IO_COMPLETION ||
        apc_called != 1 ||
        apc_error != 0 ||
        apc_overlapped != &overlapped ||
        !notification_matches(
            buffer.bytes,
            apc_bytes,
            sizeof(buffer.bytes),
            apc_name
        )) {
        goto done;
    }
    ok = TRUE;

done:
    CloseHandle(directory);
    return ok;
}

static BOOL test_overflow(const WCHAR *directory_path) {
    union {
        ULONG_PTR alignment;
        unsigned char bytes[16];
    } buffer;
    OVERLAPPED overlapped;
    HANDLE directory = INVALID_HANDLE_VALUE;
    HANDLE event = NULL;
    DWORD transferred = 0xffffffffUL;
    BOOL ok = FALSE;

    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (directory == INVALID_HANDLE_VALUE || !event) {
        goto done;
    }
    init_overlapped(&overlapped, event);
    if (!arm_directory_read(
            directory,
            buffer.bytes,
            sizeof(buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME,
            &overlapped,
            NULL
        ) ||
        !create_named_file(directory_path, overflow_name) ||
        !GetOverlappedResultEx(
            directory,
            &overlapped,
            &transferred,
            2000,
            FALSE
        ) ||
        transferred != 0 ||
        WaitForSingleObject(event, 0) != WAIT_OBJECT_0) {
        goto done;
    }
    ok = TRUE;

done:
    if (directory != INVALID_HANDLE_VALUE) {
        CloseHandle(directory);
    }
    if (event) {
        CloseHandle(event);
    }
    return ok;
}

static BOOL test_invalid_parameters(const WCHAR *directory_path) {
    union {
        ULONG_PTR alignment;
        unsigned char bytes[1024];
    } buffer;
    OVERLAPPED overlapped;
    HANDLE directory;
    HANDLE event;
    BOOL result;
    DWORD error;
    DWORD failures = 0;

    SetLastError(0);
    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_OVERLAPPED
    );
    if (directory != INVALID_HANDLE_VALUE ||
        GetLastError() != ERROR_ACCESS_DENIED) {
        failures++;
        if (directory != INVALID_HANDLE_VALUE) {
            CloseHandle(directory);
        }
    }

    directory = open_directory(
        directory_path,
        0,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (directory == INVALID_HANDLE_VALUE || !event) {
        failures++;
    } else {
        init_overlapped(&overlapped, event);
        SetLastError(0);
        result = arm_directory_read(
            directory,
            buffer.bytes,
            sizeof(buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME,
            &overlapped,
            NULL
        );
        error = GetLastError();
        if (result || error != ERROR_ACCESS_DENIED) {
            failures++;
            if (result) {
                CancelIoEx(directory, &overlapped);
            }
        }
    }
    if (directory != INVALID_HANDLE_VALUE) {
        CloseHandle(directory);
    }
    if (event) {
        CloseHandle(event);
    }

    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (directory == INVALID_HANDLE_VALUE || !event) {
        failures++;
    } else {
        init_overlapped(&overlapped, event);
        SetLastError(0);
        result = arm_directory_read(
            directory,
            buffer.bytes,
            sizeof(buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME | 0x00000200,
            &overlapped,
            NULL
        );
        error = GetLastError();
        if (result || error != ERROR_INVALID_PARAMETER) {
            failures++;
            if (result) {
                CancelIoEx(directory, &overlapped);
            }
        }
    }
    if (directory != INVALID_HANDLE_VALUE) {
        CloseHandle(directory);
    }
    if (event) {
        CloseHandle(event);
    }
    return failures == 0;
}

static BOOL test_rearm(const WCHAR *directory_path) {
    union {
        ULONG_PTR alignment;
        unsigned char bytes[1024];
    } first_buffer, queued_buffer;
    OVERLAPPED first_overlapped;
    OVERLAPPED queued_overlapped;
    HANDLE directory = INVALID_HANDLE_VALUE;
    HANDLE first_event = NULL;
    HANDLE queued_event = NULL;
    DWORD transferred = 0;
    BOOL ok = FALSE;

    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    first_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    queued_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (directory == INVALID_HANDLE_VALUE || !first_event || !queued_event) {
        goto done;
    }
    init_overlapped(&first_overlapped, first_event);
    if (!arm_directory_read(
            directory,
            first_buffer.bytes,
            sizeof(first_buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            &first_overlapped,
            NULL
        ) ||
        !create_named_file(directory_path, rearm_first_name) ||
        !GetOverlappedResultEx(
            directory,
            &first_overlapped,
            &transferred,
            2000,
            FALSE
        ) ||
        !notification_matches(
            first_buffer.bytes,
            transferred,
            sizeof(first_buffer.bytes),
            rearm_first_name
        ) ||
        !create_named_file(directory_path, rearm_queued_name)) {
        goto done;
    }
    init_overlapped(&queued_overlapped, queued_event);
    if (!arm_directory_read(
            directory,
            queued_buffer.bytes,
            sizeof(queued_buffer.bytes),
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            &queued_overlapped,
            NULL
        ) ||
        !GetOverlappedResultEx(
            directory,
            &queued_overlapped,
            &transferred,
            2000,
            FALSE
        ) ||
        !notification_matches(
            queued_buffer.bytes,
            transferred,
            sizeof(queued_buffer.bytes),
            rearm_queued_name
        ) ||
        WaitForSingleObject(queued_event, 0) != WAIT_OBJECT_0) {
        goto done;
    }
    ok = TRUE;

done:
    if (directory != INVALID_HANDLE_VALUE) {
        CloseHandle(directory);
    }
    if (first_event) {
        CloseHandle(first_event);
    }
    if (queued_event) {
        CloseHandle(queued_event);
    }
    return ok;
}

void raven_entry(void) {
    WCHAR directory_path[520];
    union {
        ULONG_PTR alignment;
        unsigned char bytes[1024];
    } change_buffer, cancel_buffer;
    OVERLAPPED change_overlapped;
    OVERLAPPED cancel_overlapped;
    HANDLE directory;
    HANDLE cancel_directory;
    HANDLE worker;
    DWORD transferred = 0;
    DWORD worker_tid;
    DWORD failures = 0;

    init_overlapped(&change_overlapped, NULL);
    init_overlapped(&cancel_overlapped, NULL);
    if (!read_directory_path(directory_path, 520) ||
        !build_change_path(
            directory_path,
            change_name,
            change_path,
            520
        )) {
        ExitProcess(10);
    }
    directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    if (directory == INVALID_HANDLE_VALUE) {
        ExitProcess(11);
    }
    worker_start = CreateEventW(NULL, TRUE, FALSE, NULL);
    change_overlapped.event = CreateEventW(NULL, TRUE, FALSE, NULL);
    cancel_overlapped.event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!worker_start || !change_overlapped.event || !cancel_overlapped.event) {
        ExitProcess(12);
    }
    worker = CreateThread(NULL, 0, worker_main, NULL, 0, &worker_tid);
    if (!worker || !worker_tid) {
        ExitProcess(13);
    }

    if (!ReadDirectoryChangesW(
            directory,
            change_buffer.bytes,
            sizeof(change_buffer.bytes),
            FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            NULL,
            &change_overlapped,
            NULL
        )) {
        ExitProcess(20);
    }
    SetLastError(0);
    if (GetOverlappedResult(
            directory,
            &change_overlapped,
            &transferred,
            FALSE
        ) ||
        GetLastError() != ERROR_IO_INCOMPLETE) {
        ExitProcess(21);
    }
    if (WaitForSingleObject(change_overlapped.event, 0) != WAIT_TIMEOUT) {
        ExitProcess(22);
    }
    if (!SetEvent(worker_start)) {
        ExitProcess(23);
    }
    if (!GetOverlappedResult(
            directory,
            &change_overlapped,
            &transferred,
            TRUE
        )) {
        ExitProcess(24);
    }
    if (!notification_matches(
            change_buffer.bytes,
            transferred,
            sizeof(change_buffer.bytes),
            change_name
        )) {
        ExitProcess(25);
    }
    if (WaitForSingleObject(change_overlapped.event, 0) != WAIT_OBJECT_0) {
        ExitProcess(26);
    }
    if (WaitForSingleObject(worker, INFINITE) != WAIT_OBJECT_0 ||
        worker_result != 5) {
        ExitProcess(27 + worker_result);
    }

    cancel_directory = open_directory(
        directory_path,
        FILE_LIST_DIRECTORY,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED
    );
    if (cancel_directory == INVALID_HANDLE_VALUE) {
        ExitProcess(39);
    }
    if (!ReadDirectoryChangesW(
            cancel_directory,
            cancel_buffer.bytes,
            sizeof(cancel_buffer.bytes),
            FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME |
                FILE_NOTIFY_CHANGE_SIZE |
                FILE_NOTIFY_CHANGE_LAST_WRITE,
            NULL,
            &cancel_overlapped,
            NULL
        )) {
        ExitProcess(40);
    }
    if (!CancelIoEx(cancel_directory, &cancel_overlapped)) {
        ExitProcess(41);
    }
    SetLastError(0);
    if (GetOverlappedResult(
            cancel_directory,
            &cancel_overlapped,
            &transferred,
            TRUE
        ) ||
        GetLastError() != ERROR_OPERATION_ABORTED) {
        ExitProcess(42);
    }
    if (WaitForSingleObject(cancel_overlapped.event, 0) != WAIT_OBJECT_0) {
        ExitProcess(43);
    }

    if (!CloseHandle(worker) ||
        !CloseHandle(worker_start) ||
        !CloseHandle(change_overlapped.event) ||
        !CloseHandle(cancel_overlapped.event) ||
        !CloseHandle(cancel_directory) ||
        !CloseHandle(directory)) {
        ExitProcess(50);
    }
    if (!test_iocp(directory_path)) {
        failures |= FAILURE_IOCP;
    }
    if (!test_result_ex(directory_path)) {
        failures |= FAILURE_RESULT_EX;
    }
    if (!test_apc(directory_path)) {
        failures |= FAILURE_APC;
    }
    if (!test_overflow(directory_path)) {
        failures |= FAILURE_OVERFLOW;
    }
    if (!test_invalid_parameters(directory_path)) {
        failures |= FAILURE_INVALID;
    }
    if (!test_rearm(directory_path)) {
        failures |= FAILURE_REARM;
    }
    ExitProcess(failures);
}

#ifdef _WIN64
#define WINAPI
#define CALLBACK
#else
#define WINAPI __attribute__((stdcall))
#define CALLBACK __attribute__((stdcall))
#endif

#define DLLIMPORT __declspec(dllimport)
#define NULL ((void *)0)

typedef int BOOL;
typedef unsigned short ATOM;
typedef unsigned int UINT;
typedef unsigned long DWORD;
typedef long LONG;
#ifdef _WIN64
typedef unsigned long long UINT_PTR;
typedef long long LONG_PTR;
#else
typedef unsigned long UINT_PTR;
typedef long LONG_PTR;
#endif
typedef void *HANDLE;
typedef void *HWND;
typedef void *HINSTANCE;
typedef void *HICON;
typedef void *HCURSOR;
typedef void *HBRUSH;
typedef const unsigned short *LPCWSTR;
typedef DWORD (WINAPI *THREAD_START_ROUTINE)(void *);
typedef LONG_PTR (CALLBACK *WNDPROC)(HWND, UINT, UINT_PTR, LONG_PTR);
typedef LONG_PTR (CALLBACK *SUBCLASSPROC)(
    HWND, UINT, UINT_PTR, LONG_PTR, UINT_PTR, UINT_PTR
);

typedef struct {
    UINT style;
    WNDPROC lpfnWndProc;
    int cbClsExtra;
    int cbWndExtra;
    HINSTANCE hInstance;
    HICON hIcon;
    HCURSOR hCursor;
    HBRUSH hbrBackground;
    LPCWSTR lpszMenuName;
    LPCWSTR lpszClassName;
} WNDCLASSW;

typedef struct {
    HWND hwnd;
    UINT message;
    UINT_PTR w_param;
    LONG_PTR l_param;
    DWORD time;
    LONG point_x;
    LONG point_y;
    DWORD private_value;
} MSG;

DLLIMPORT HANDLE WINAPI CreateThread(
    void *, UINT_PTR, THREAD_START_ROUTINE, void *, DWORD, DWORD *
);
DLLIMPORT DWORD WINAPI GetCurrentThreadId(void);
DLLIMPORT DWORD WINAPI GetTickCount(void);
DLLIMPORT DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE);
DLLIMPORT HANDLE WINAPI CreateEventW(void *, BOOL, BOOL, LPCWSTR);
DLLIMPORT BOOL WINAPI SetEvent(HANDLE);
DLLIMPORT void WINAPI Sleep(DWORD);
DLLIMPORT void WINAPI ExitProcess(UINT);
DLLIMPORT HINSTANCE WINAPI GetModuleHandleW(LPCWSTR);
DLLIMPORT ATOM WINAPI RegisterClassW(const WNDCLASSW *);
DLLIMPORT HWND WINAPI CreateWindowExW(
    DWORD, LPCWSTR, LPCWSTR, DWORD, int, int, int, int,
    HWND, void *, HINSTANCE, void *
);
DLLIMPORT BOOL WINAPI DestroyWindow(HWND);
DLLIMPORT BOOL WINAPI PostMessageW(HWND, UINT, UINT_PTR, LONG_PTR);
DLLIMPORT BOOL WINAPI PeekMessageW(MSG *, HWND, UINT, UINT, UINT);
DLLIMPORT DWORD WINAPI MsgWaitForMultipleObjects(
    DWORD, const HANDLE *, BOOL, DWORD, DWORD
);
DLLIMPORT DWORD WINAPI MsgWaitForMultipleObjectsEx(
    DWORD, const HANDLE *, DWORD, DWORD, DWORD
);
DLLIMPORT LONG_PTR WINAPI DispatchMessageW(const MSG *);
DLLIMPORT LONG_PTR WINAPI DefWindowProcW(HWND, UINT, UINT_PTR, LONG_PTR);
DLLIMPORT LONG_PTR WINAPI SendMessageA(HWND, UINT, UINT_PTR, LONG_PTR);
DLLIMPORT LONG_PTR WINAPI SendMessageW(HWND, UINT, UINT_PTR, LONG_PTR);
DLLIMPORT BOOL WINAPI InSendMessage(void);
DLLIMPORT DWORD WINAPI InSendMessageEx(void *);
DLLIMPORT BOOL WINAPI ReplyMessage(LONG_PTR);
DLLIMPORT LONG_PTR WINAPI DialogBoxParamW(
    HINSTANCE, LPCWSTR, HWND, WNDPROC, LONG_PTR
);
DLLIMPORT BOOL WINAPI EndDialog(HWND, LONG_PTR);
DLLIMPORT BOOL WINAPI SetWindowSubclass(
    HWND, SUBCLASSPROC, UINT_PTR, UINT_PTR
);
DLLIMPORT LONG_PTR WINAPI DefSubclassProc(HWND, UINT, UINT_PTR, LONG_PTR);

#define PM_REMOVE 0x0001
#define QS_POSTMESSAGE 0x0008
#define QS_TIMER 0x0010
#define QS_ALLINPUT 0x04ff
#define MWMO_INPUTAVAILABLE 0x0004
#define TRUE 1
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 0x0102
#define INFINITE 0xffffffffUL
#define WM_INITDIALOG 0x0110
#define WM_COMMAND 0x0111
#define WM_APP 0x8000
#define TEST_MESSAGE (WM_APP + 17)
#define TEST_REPLY_MESSAGE (WM_APP + 18)
#define TEST_REENTRANT_MESSAGE (WM_APP + 19)
#define TEST_NESTED_MESSAGE (WM_APP + 20)
#ifdef _WIN64
#define TEST_RESULT ((LONG_PTR)0x13579bdf2468ace0LL)
#else
#define TEST_RESULT ((LONG_PTR)0x13579bdf)
#endif
#define TEST_REPLY_RESULT ((LONG_PTR)0x2468ace1)
#define TEST_REENTRANT_RESULT ((LONG_PTR)0x3579bdf2)
#define TEST_NESTED_RESULT ((LONG_PTR)0x468ace13)
#define MODAL_RESULT ((LONG_PTR)0x3579bdf1)
#define MODAL_RESOURCE ((LPCWSTR)(UINT_PTR)101)

static const unsigned short class_name[] = {
    'R', 'a', 'v', 'e', 'n', 'S', 'e', 'n', 'd', 'T', 'e', 's', 't', 0
};
static const unsigned short window_name[] = {
    's', 'e', 'n', 'd', 0
};
static const unsigned short main_class_name[] = {
    'R', 'a', 'v', 'e', 'n', 'S', 'e', 'n', 'd', 'M', 'a', 'i', 'n', 0
};

static volatile HWND owner_window;
static volatile HWND main_window;
static volatile DWORD owner_tid;
static volatile DWORD main_tid;
static volatile DWORD subclass_tid;
static volatile DWORD subclass_calls;
static volatile DWORD original_calls;
static volatile DWORD nested_tid;
static volatile DWORD nested_calls;
static volatile DWORD worker_ready;
static volatile DWORD worker_stop;
static volatile DWORD worker_result;
static volatile DWORD reply_done;
static volatile HWND modal_window;
static volatile DWORD modal_owner_tid;
static volatile DWORD modal_dispatch_tid;
static volatile DWORD modal_ready;
static volatile DWORD modal_calls;
static volatile DWORD modal_result;

static LONG_PTR CALLBACK base_wnd_proc(
    HWND hwnd, UINT message, UINT_PTR w_param, LONG_PTR l_param
) {
    if (message == TEST_MESSAGE) {
        original_calls++;
        return 0x2468ace0;
    }
    return DefWindowProcW(hwnd, message, w_param, l_param);
}

static LONG_PTR CALLBACK main_wnd_proc(
    HWND hwnd, UINT message, UINT_PTR w_param, LONG_PTR l_param
) {
    if (message == TEST_NESTED_MESSAGE) {
        if (w_param != 0x12345678 || l_param != 0x23456789) {
            return 0x10203040;
        }
        nested_tid = GetCurrentThreadId();
        nested_calls++;
        return TEST_NESTED_RESULT;
    }
    return DefWindowProcW(hwnd, message, w_param, l_param);
}

static LONG_PTR CALLBACK subclass_proc(
    HWND hwnd,
    UINT message,
    UINT_PTR w_param,
    LONG_PTR l_param,
    UINT_PTR subclass_id,
    UINT_PTR reference_data
) {
    if (message == TEST_MESSAGE) {
        if (w_param != 0x11223344 || l_param != 0x55667788 ||
            subclass_id != 7 || reference_data != 0xaabbccdd) {
            return 0x10203040;
        }
        subclass_tid = GetCurrentThreadId();
        subclass_calls++;
        Sleep(75);
        return TEST_RESULT;
    }
    if (message == TEST_REPLY_MESSAGE) {
        if (!InSendMessage() || InSendMessageEx(NULL) != 1) {
            return 0x11223344;
        }
        if (!ReplyMessage(TEST_REPLY_RESULT) || InSendMessageEx(NULL) != 9) {
            return 0x22334455;
        }
        Sleep(150);
        reply_done = 1;
        return 0x33445566;
    }
    if (message == TEST_REENTRANT_MESSAGE) {
        LONG_PTR result = SendMessageW(
            (HWND)main_window, TEST_NESTED_MESSAGE, 0x12345678, 0x23456789
        );
        if (result != TEST_NESTED_RESULT) {
            return 0x44556677;
        }
        return TEST_REENTRANT_RESULT;
    }
    return DefSubclassProc(hwnd, message, w_param, l_param);
}

static DWORD WINAPI owner_thread(void *parameter) {
    WNDCLASSW window_class;
    MSG message;
    HWND window;
    (void)parameter;

    window_class.style = 0;
    window_class.lpfnWndProc = base_wnd_proc;
    window_class.cbClsExtra = 0;
    window_class.cbWndExtra = 0;
    window_class.hInstance = NULL;
    window_class.hIcon = NULL;
    window_class.hCursor = NULL;
    window_class.hbrBackground = NULL;
    window_class.lpszMenuName = NULL;
    window_class.lpszClassName = class_name;

    owner_tid = GetCurrentThreadId();
    if (!RegisterClassW(&window_class)) {
        worker_result = 1;
        worker_ready = 1;
        return 1;
    }
    window = CreateWindowExW(
        0, class_name, window_name, 0,
        0, 0, 160, 80, NULL, NULL, NULL, NULL
    );
    if (!window) {
        worker_result = 2;
        worker_ready = 1;
        return 2;
    }
    if (!SetWindowSubclass(window, subclass_proc, 7, 0xaabbccdd)) {
        worker_result = 3;
        worker_ready = 1;
        return 3;
    }

    owner_window = window;
    worker_ready = 1;
    while (!worker_stop) {
        MsgWaitForMultipleObjects(0, NULL, 0, 16, QS_ALLINPUT);
        while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
            DispatchMessageW(&message);
        }
    }
    DestroyWindow(window);
    return worker_result;
}

static LONG_PTR CALLBACK modal_dialog_proc(
    HWND hwnd, UINT message, UINT_PTR w_param, LONG_PTR l_param
) {
    (void)l_param;
    if (message == WM_INITDIALOG) {
        modal_window = hwnd;
        modal_ready = 1;
        return 1;
    }
    if (message == TEST_MESSAGE) {
        if (w_param != 0x12344321) {
            return 0x10203040;
        }
        modal_dispatch_tid = GetCurrentThreadId();
        modal_calls++;
        Sleep(75);
        return MODAL_RESULT;
    }
    if (message == WM_COMMAND && (w_param & 0xffff) == 2) {
        EndDialog(hwnd, 42);
        return 1;
    }
    return 0;
}

static DWORD WINAPI modal_owner_thread(void *parameter) {
    LONG_PTR result;
    (void)parameter;

    modal_owner_tid = GetCurrentThreadId();
    result = DialogBoxParamW(
        GetModuleHandleW(NULL),
        MODAL_RESOURCE,
        NULL,
        modal_dialog_proc,
        0
    );
    modal_result = (DWORD)result;
    return result == 42 ? 0 : 1;
}

void raven_entry(void) {
    HANDLE worker;
    WNDCLASSW window_class;
    DWORD worker_id;
    DWORD attempts;
    DWORD started;
    DWORD elapsed;
    LONG_PTR result;
    HANDLE wait_event;
    MSG queued_message;

    window_class.style = 0;
    window_class.lpfnWndProc = main_wnd_proc;
    window_class.cbClsExtra = 0;
    window_class.cbWndExtra = 0;
    window_class.hInstance = NULL;
    window_class.hIcon = NULL;
    window_class.hCursor = NULL;
    window_class.hbrBackground = NULL;
    window_class.lpszMenuName = NULL;
    window_class.lpszClassName = main_class_name;
    main_tid = GetCurrentThreadId();
    if (!RegisterClassW(&window_class)) {
        ExitProcess(7);
    }
    main_window = CreateWindowExW(
        0, main_class_name, window_name, 0,
        0, 0, 160, 80, NULL, NULL, NULL, NULL
    );
    if (!main_window) {
        ExitProcess(8);
    }
    wait_event = CreateEventW(NULL, 0, 0, NULL);
    if (!wait_event) {
        ExitProcess(9);
    }
    if (MsgWaitForMultipleObjects(1, &wait_event, 0, 0, 0) != WAIT_TIMEOUT ||
        !SetEvent(wait_event) ||
        MsgWaitForMultipleObjects(1, &wait_event, 0, 0, 0) != WAIT_OBJECT_0 ||
        MsgWaitForMultipleObjectsEx(1, &wait_event, 0, 0, 0) != WAIT_TIMEOUT ||
        !SetEvent(wait_event) ||
        MsgWaitForMultipleObjectsEx(1, &wait_event, 0, 0, 0) != WAIT_OBJECT_0) {
        ExitProcess(9);
    }
    if (!PostMessageW(main_window, WM_APP + 99, 0, 0) ||
        MsgWaitForMultipleObjects(0, NULL, 0, 0, QS_TIMER) != WAIT_TIMEOUT ||
        !SetEvent(wait_event) ||
        MsgWaitForMultipleObjects(
            1, &wait_event, TRUE, 0, QS_POSTMESSAGE
        ) != WAIT_OBJECT_0 ||
        MsgWaitForMultipleObjectsEx(
            0, NULL, 0, QS_POSTMESSAGE, MWMO_INPUTAVAILABLE
        ) != WAIT_OBJECT_0 ||
        !PeekMessageW(
            &queued_message, main_window, WM_APP + 99, WM_APP + 99, PM_REMOVE
        )) {
        ExitProcess(9);
    }
    CloseHandle(wait_event);

    worker = CreateThread(NULL, 0, owner_thread, NULL, 0, &worker_id);
    if (!worker) {
        ExitProcess(10);
    }
    for (attempts = 0; attempts < 5000 && !worker_ready; attempts++) {
        Sleep(1);
    }
    if (!worker_ready || worker_result != 0 || !owner_window ||
        owner_tid != worker_id) {
        ExitProcess(11 + worker_result);
    }

    started = GetTickCount();
    result = SendMessageA(
        (HWND)owner_window, TEST_MESSAGE, 0x11223344, 0x55667788
    );
    elapsed = GetTickCount() - started;
    if (result != TEST_RESULT) {
        ExitProcess(20);
    }
    if (subclass_calls != 1 || subclass_tid != owner_tid ||
        subclass_tid == GetCurrentThreadId()) {
        ExitProcess(21);
    }
    if (original_calls != 0) {
        ExitProcess(22);
    }
    if (elapsed < 70) {
        ExitProcess(23);
    }

    started = GetTickCount();
    result = SendMessageW(
        (HWND)owner_window, TEST_REPLY_MESSAGE, 0, 0
    );
    elapsed = GetTickCount() - started;
    if (result != TEST_REPLY_RESULT || elapsed >= 120) {
        ExitProcess(25);
    }
    for (attempts = 0; attempts < 5000 && !reply_done; attempts++) {
        Sleep(1);
    }
    if (!reply_done) {
        ExitProcess(26);
    }

    result = SendMessageW(
        (HWND)owner_window, TEST_REENTRANT_MESSAGE, 0, 0
    );
    if (result != TEST_REENTRANT_RESULT) {
        ExitProcess(27);
    }
    if (nested_calls != 1 || nested_tid != main_tid ||
        nested_tid == owner_tid) {
        ExitProcess(28);
    }

    worker_stop = 1;
    if (WaitForSingleObject(worker, INFINITE) != WAIT_OBJECT_0 ||
        worker_result != 0) {
        ExitProcess(24);
    }
    CloseHandle(worker);

    worker = CreateThread(NULL, 0, modal_owner_thread, NULL, 0, &worker_id);
    if (!worker) {
        ExitProcess(30);
    }
    for (attempts = 0; attempts < 5000 && !modal_ready; attempts++) {
        Sleep(1);
    }
    if (!modal_ready || !modal_window || modal_owner_tid != worker_id) {
        ExitProcess(31);
    }

    started = GetTickCount();
    result = SendMessageW(
        (HWND)modal_window, TEST_MESSAGE, 0x12344321, 0x87655678
    );
    elapsed = GetTickCount() - started;
    if (result != MODAL_RESULT || modal_calls != 1) {
        ExitProcess(32);
    }
    if (modal_dispatch_tid != modal_owner_tid ||
        modal_dispatch_tid == GetCurrentThreadId()) {
        ExitProcess(33);
    }
    if (elapsed < 70) {
        ExitProcess(34);
    }
    if (SendMessageW((HWND)modal_window, WM_COMMAND, 2, 0) != 1) {
        ExitProcess(35);
    }
    if (WaitForSingleObject(worker, INFINITE) != WAIT_OBJECT_0 ||
        modal_result != 42) {
        ExitProcess(36);
    }
    CloseHandle(worker);
    ExitProcess(0);
}

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
#ifdef _WIN64
typedef unsigned long long UINT_PTR;
typedef long long LONG_PTR;
#else
typedef unsigned long UINT_PTR;
typedef long LONG_PTR;
#endif
typedef void *HANDLE;
typedef void *HWND;
typedef DWORD (WINAPI *THREAD_START_ROUTINE)(void *);
typedef void (WINAPI *TIMER_PROC)(HWND, UINT, UINT_PTR, DWORD);

typedef struct {
    HWND hwnd;
    UINT message;
    UINT_PTR w_param;
    LONG_PTR l_param;
    DWORD time;
    long point_x;
    long point_y;
    DWORD private_value;
} MSG;

DLLIMPORT HANDLE WINAPI CreateThread(
    void *, UINT_PTR, THREAD_START_ROUTINE, void *, DWORD, DWORD *
);
DLLIMPORT DWORD WINAPI GetCurrentThreadId(void);
DLLIMPORT DWORD WINAPI WaitForSingleObject(HANDLE, DWORD);
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE);
DLLIMPORT void WINAPI Sleep(DWORD);
DLLIMPORT void WINAPI ExitProcess(UINT);
DLLIMPORT BOOL WINAPI PostThreadMessageW(DWORD, UINT, UINT_PTR, LONG_PTR);
DLLIMPORT BOOL WINAPI PostMessageW(HWND, UINT, UINT_PTR, LONG_PTR);
DLLIMPORT BOOL WINAPI PeekMessageW(MSG *, HWND, UINT, UINT, UINT);
DLLIMPORT void WINAPI PostQuitMessage(int);
DLLIMPORT UINT_PTR WINAPI SetTimer(HWND, UINT_PTR, UINT, TIMER_PROC);
DLLIMPORT BOOL WINAPI KillTimer(HWND, UINT_PTR);
DLLIMPORT LONG_PTR WINAPI DispatchMessageW(const MSG *);

#define PM_REMOVE 0x0001
#define WAIT_OBJECT_0 0
#define INFINITE 0xffffffffUL
#define WM_QUIT 0x0012
#define WM_TIMER 0x0113
#define WM_APP 0x8000

static volatile DWORD worker_ready;
static volatile DWORD worker_tid;
static volatile DWORD worker_result;
static volatile DWORD timer_fired;
static volatile UINT_PTR expected_timer_id;

static DWORD WINAPI worker_main(void *parameter) {
    MSG message;
    UINT attempts;
    (void)parameter;

    worker_tid = GetCurrentThreadId();
    worker_ready = 1;
    for (attempts = 0; attempts < 5000; attempts++) {
        if (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
            if (message.message != WM_APP + 1 ||
                message.hwnd != NULL ||
                message.w_param != 0x1234 ||
                message.l_param != 0x5678) {
                worker_result = 10;
                return 10;
            }
            PostQuitMessage(37);
            if (!PeekMessageW(&message, NULL, 0, 0, PM_REMOVE) ||
                message.message != WM_QUIT ||
                message.w_param != 37) {
                worker_result = 11;
                return 11;
            }
            worker_result = 1;
            return 0;
        }
        Sleep(1);
    }
    worker_result = 12;
    return 12;
}

static void WINAPI timer_proc(
    HWND hwnd,
    UINT message,
    UINT_PTR timer_id,
    DWORD message_time
) {
    if (hwnd == NULL &&
        message == WM_TIMER &&
        timer_id == expected_timer_id &&
        message_time != 0) {
        timer_fired = 1;
    } else {
        timer_fired = 2;
    }
}

void raven_entry(void) {
    HANDLE worker;
    DWORD tid;
    MSG message;
    UINT attempts;

    worker = CreateThread(NULL, 0, worker_main, NULL, 0, &tid);
    if (!worker) {
        ExitProcess(20);
    }
    for (attempts = 0; attempts < 5000 && !worker_ready; attempts++) {
        Sleep(1);
    }
    if (!worker_ready || worker_tid != tid) {
        ExitProcess(21);
    }
    if (!PostThreadMessageW(tid, WM_APP + 1, 0x1234, 0x5678)) {
        ExitProcess(22);
    }
    if (WaitForSingleObject(worker, INFINITE) != WAIT_OBJECT_0 ||
        worker_result != 1) {
        ExitProcess(23 + worker_result);
    }
    CloseHandle(worker);
    if (PostThreadMessageW(tid, WM_APP + 1, 0, 0)) {
        ExitProcess(39);
    }

    if (!PostMessageW(NULL, WM_APP + 2, 0xabcd, 0x1357) ||
        !PeekMessageW(&message, NULL, 0, 0, PM_REMOVE) ||
        message.message != WM_APP + 2 ||
        message.hwnd != NULL ||
        message.w_param != 0xabcd ||
        message.l_param != 0x1357) {
        ExitProcess(40);
    }

    expected_timer_id = SetTimer(NULL, 0, 10, timer_proc);
    if (!expected_timer_id) {
        ExitProcess(41);
    }
    for (attempts = 0; attempts < 5000 && !timer_fired; attempts++) {
        if (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE) &&
            message.message == WM_TIMER) {
            DispatchMessageW(&message);
        }
        Sleep(1);
    }
    if (timer_fired != 1) {
        ExitProcess(42 + timer_fired);
    }
    if (!KillTimer(NULL, expected_timer_id)) {
        ExitProcess(45);
    }
    ExitProcess(0);
}

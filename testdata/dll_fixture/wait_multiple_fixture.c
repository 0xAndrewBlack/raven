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
typedef __UINTPTR_TYPE__ ULONG_PTR;
typedef void *HANDLE;

DLLIMPORT HANDLE WINAPI CreateEventW(void *, BOOL, BOOL, const unsigned short *);
DLLIMPORT BOOL WINAPI SetEvent(HANDLE);
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE);
DLLIMPORT HANDLE WINAPI GetCurrentThread(void);
DLLIMPORT DWORD WINAPI GetCurrentThreadId(void);
DLLIMPORT HANDLE WINAPI OpenThread(DWORD, BOOL, DWORD);
DLLIMPORT DWORD WINAPI QueueUserAPC(void (WINAPI *)(ULONG_PTR), HANDLE, ULONG_PTR);
DLLIMPORT DWORD WINAPI SleepEx(DWORD, BOOL);
DLLIMPORT DWORD WINAPI WaitForSingleObjectEx(HANDLE, DWORD, BOOL);
DLLIMPORT DWORD WINAPI WaitForMultipleObjects(DWORD, const HANDLE *, BOOL, DWORD);
DLLIMPORT DWORD WINAPI WaitForMultipleObjectsEx(DWORD, const HANDLE *, BOOL, DWORD, BOOL);
DLLIMPORT void WINAPI ExitProcess(UINT);

#define FALSE 0
#define TRUE 1
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 0x102
#define WAIT_IO_COMPLETION 0xc0
#define THREAD_SET_CONTEXT 0x0010

static volatile ULONG_PTR apc_value;

static void WINAPI raven_apc(ULONG_PTR value) {
    apc_value = value;
}

void raven_entry(void) {
    HANDLE handles[2];
    HANDLE current_thread;
    DWORD result;

    handles[0] = CreateEventW(NULL, TRUE, FALSE, NULL);
    handles[1] = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (!handles[0] || !handles[1]) {
        ExitProcess(10);
    }

    current_thread = OpenThread(THREAD_SET_CONTEXT, FALSE, GetCurrentThreadId());
    if (!current_thread) {
        ExitProcess(16);
    }
    if (!QueueUserAPC(raven_apc, current_thread, 0x11223344)) {
        ExitProcess(17);
    }
    result = SleepEx(1000, TRUE);
    if (result != WAIT_IO_COMPLETION || apc_value != 0x11223344) {
        ExitProcess(18);
    }
    if (!CloseHandle(current_thread)) {
        ExitProcess(19);
    }

    apc_value = 0;
    if (!QueueUserAPC(raven_apc, GetCurrentThread(), 0x22334455)) {
        ExitProcess(20);
    }
    result = WaitForSingleObjectEx(handles[0], 1000, TRUE);
    if (result != WAIT_IO_COMPLETION || apc_value != 0x22334455) {
        ExitProcess(21);
    }

    apc_value = 0;
    if (!QueueUserAPC(raven_apc, GetCurrentThread(), 0x33445566)) {
        ExitProcess(22);
    }
    result = WaitForMultipleObjectsEx(2, handles, TRUE, 1000, TRUE);
    if (result != WAIT_IO_COMPLETION || apc_value != 0x33445566) {
        ExitProcess(23);
    }

    result = WaitForMultipleObjects(2, handles, FALSE, 1000);
    if (result != WAIT_OBJECT_0 + 1) {
        ExitProcess(11);
    }
    result = WaitForMultipleObjectsEx(2, handles, FALSE, 1000, FALSE);
    if (result != WAIT_OBJECT_0 + 1) {
        ExitProcess(12);
    }
    result = WaitForMultipleObjects(2, handles, TRUE, 1);
    if (result != WAIT_TIMEOUT) {
        ExitProcess(13);
    }
    if (!SetEvent(handles[0])) {
        ExitProcess(14);
    }
    result = WaitForMultipleObjectsEx(2, handles, TRUE, 1000, FALSE);
    if (result != WAIT_OBJECT_0) {
        ExitProcess(15);
    }

    CloseHandle(handles[0]);
    CloseHandle(handles[1]);
    ExitProcess(0);
}

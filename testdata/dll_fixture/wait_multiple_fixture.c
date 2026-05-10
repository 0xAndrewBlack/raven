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
typedef void *HANDLE;

DLLIMPORT HANDLE WINAPI CreateEventW(void *, BOOL, BOOL, const unsigned short *);
DLLIMPORT BOOL WINAPI SetEvent(HANDLE);
DLLIMPORT BOOL WINAPI CloseHandle(HANDLE);
DLLIMPORT DWORD WINAPI WaitForMultipleObjects(DWORD, const HANDLE *, BOOL, DWORD);
DLLIMPORT DWORD WINAPI WaitForMultipleObjectsEx(DWORD, const HANDLE *, BOOL, DWORD, BOOL);
DLLIMPORT void WINAPI ExitProcess(UINT);

#define FALSE 0
#define TRUE 1
#define WAIT_OBJECT_0 0
#define WAIT_TIMEOUT 0x102

void raven_entry(void) {
    HANDLE handles[2];
    DWORD result;

    handles[0] = CreateEventW(NULL, TRUE, FALSE, NULL);
    handles[1] = CreateEventW(NULL, TRUE, TRUE, NULL);
    if (!handles[0] || !handles[1]) {
        ExitProcess(10);
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

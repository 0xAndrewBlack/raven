#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0602
#include <windows.h>

static DWORD receiver;
static unsigned sent, apcs;
static HWND target;

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_NCCREATE) return TRUE;
	if (message == WM_APP + 3) {
		if (GetCurrentThreadId() != receiver) return -1;
		++sent;
		return wparam + lparam;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

static DWORD WINAPI sender(void *unused)
{
	(void)unused;
	return SendMessageW(target, WM_APP + 3, 17, 19) == 36 ? 0 : 1;
}

static void CALLBACK completion(ULONG_PTR value)
{
	if (value == 23) ++apcs;
}

int raven_entry(void)
{
	MSG message;
	receiver = GetCurrentThreadId();
	while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {}
	GetQueueStatus(QS_ALLINPUT | QS_ALLPOSTMESSAGE);
	if (!PostThreadMessageW(receiver, WM_APP + 1, 7, 9)) return 10;
	if (MsgWaitForMultipleObjects(0, NULL, FALSE, 0, QS_SENDMESSAGE) != WAIT_TIMEOUT) return 11;
	SetLastError(0);
	if (PeekMessageA(&message, NULL, 0, 0, PM_REMOVE | PM_QS_SENDMESSAGE) || GetLastError()) return 12;
	if (GetQueueStatus(QS_SENDMESSAGE) || GetInputState()) return 13;
	const DWORD posted = QS_POSTMESSAGE | QS_ALLPOSTMESSAGE;
	/* A filtered peek observes QS_POSTMESSAGE, but leaves QS_ALLPOSTMESSAGE new. */
	if (GetQueueStatus(posted) != (posted << 16 | QS_ALLPOSTMESSAGE)) return 14;
	if (GetQueueStatus(posted) != posted << 16) return 15;
	if (MsgWaitForMultipleObjects(0, NULL, FALSE, 0, QS_POSTMESSAGE) != WAIT_TIMEOUT) return 16;
	if (MsgWaitForMultipleObjectsEx(0, NULL, 0, QS_POSTMESSAGE, MWMO_INPUTAVAILABLE) != 0) return 17;
	if (MsgWaitForMultipleObjectsEx(0, NULL, 0, QS_SENDMESSAGE, MWMO_INPUTAVAILABLE) != WAIT_TIMEOUT) return 18;
	if (!PeekMessageW(&message, NULL, 0, 0, PM_NOREMOVE) || message.message != WM_APP + 1) return 19;
	if (MsgWaitForMultipleObjects(0, NULL, FALSE, 0, posted) != WAIT_TIMEOUT) return 20;
	if (!PostThreadMessageW(receiver, WM_APP + 2, 11, 13)) return 21;
	if (MsgWaitForMultipleObjects(0, NULL, FALSE, 0, QS_POSTMESSAGE) != 0) return 22;
	if (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE | PM_QS_PAINT)) return 23;
	if (!PeekMessageA(&message, NULL, WM_APP + 2, WM_APP + 2, PM_REMOVE | PM_NOYIELD | PM_QS_POSTMESSAGE) || message.wParam != 11) return 24;
	if (!PeekMessageA(&message, (HWND)-1, 0, 0, PM_REMOVE) || message.message != WM_APP + 1 || message.wParam != 7) return 25;
	if (GetQueueStatus(posted)) return 26;

	WNDCLASSW definition = {0};
	definition.hInstance = GetModuleHandleW(NULL);
	definition.lpfnWndProc = procedure;
	definition.lpszClassName = L"RavenQueueContract";
	if (!RegisterClassW(&definition)) return 30;
	target = CreateWindowExW(0, definition.lpszClassName, L"queue", WS_POPUP | WS_VISIBLE, 0, 0, 32, 32, NULL, NULL, definition.hInstance, NULL);
	if (!target) return 31;
	ValidateRect(target, NULL);
	while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {}
	GetQueueStatus(QS_ALLINPUT | QS_ALLPOSTMESSAGE);
	if (!InvalidateRect(target, NULL, FALSE)) return 32;
	if (GetQueueStatus(QS_PAINT) != (QS_PAINT << 16 | QS_PAINT)) return 33;
	if (MsgWaitForMultipleObjects(0, NULL, FALSE, 0, QS_SENDMESSAGE) != WAIT_TIMEOUT) return 34;
	if (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE | PM_QS_SENDMESSAGE)) return 35;
	if (!PeekMessageW(&message, NULL, 0, 0, PM_REMOVE | PM_QS_PAINT) || message.message != WM_PAINT) return 36;
	if (!ValidateRect(target, NULL) || GetQueueStatus(QS_PAINT)) return 37;
	if (!InvalidateRect(target, NULL, FALSE) || GetQueueStatus(QS_PAINT) != (QS_PAINT << 16 | QS_PAINT)) return 38;
	if (!ValidateRect(target, NULL)) return 39;

	HANDLE handles[2] = {CreateEventW(NULL, FALSE, TRUE, NULL), CreateEventW(NULL, FALSE, FALSE, NULL)};
	if (!handles[0] || !handles[1] || !PostThreadMessageW(receiver, WM_APP + 1, 0, 0)) return 40;
	if (MsgWaitForMultipleObjects(2, handles, FALSE, 0, QS_POSTMESSAGE) != 0) return 41;
	if (WaitForSingleObject(handles[0], 0) != WAIT_TIMEOUT) return 42;
	if (!SetEvent(handles[0])) return 43;
	if (MsgWaitForMultipleObjectsEx(2, handles, 0, QS_POSTMESSAGE, MWMO_WAITALL | MWMO_INPUTAVAILABLE) != WAIT_TIMEOUT) return 44;
	if (WaitForSingleObject(handles[0], 0) != 0 || !SetEvent(handles[0]) || !SetEvent(handles[1])) return 45;
	if (MsgWaitForMultipleObjectsEx(2, handles, 0, QS_SENDMESSAGE, MWMO_WAITALL | MWMO_INPUTAVAILABLE) != WAIT_TIMEOUT) return 46;
	if (MsgWaitForMultipleObjectsEx(2, handles, 0, QS_POSTMESSAGE, MWMO_WAITALL | MWMO_INPUTAVAILABLE) != 0) return 47;
	if (WaitForSingleObject(handles[0], 0) != WAIT_TIMEOUT || WaitForSingleObject(handles[1], 0) != WAIT_TIMEOUT) return 48;
	HANDLE invalid = (HANDLE)0x123456;
	SetLastError(0);
	if (MsgWaitForMultipleObjects(1, &invalid, FALSE, 0, QS_POSTMESSAGE) != WAIT_FAILED || GetLastError() != ERROR_INVALID_HANDLE) return 49;
	SetLastError(0);
	if (MsgWaitForMultipleObjectsEx(0, NULL, 0, QS_POSTMESSAGE, 8) != WAIT_FAILED || GetLastError() != ERROR_INVALID_PARAMETER) return 50;
	if (!CloseHandle(handles[0]) || !CloseHandle(handles[1])) return 51;

	HANDLE thread = CreateThread(NULL, 0, sender, NULL, 0, NULL);
	if (!thread) return 60;
	if (MsgWaitForMultipleObjects(0, NULL, FALSE, 1000, QS_SENDMESSAGE) != 0) return 61;
	if (PeekMessageA(&message, NULL, 0, 0, PM_REMOVE | PM_QS_SENDMESSAGE) || sent != 1) return 62;
	if (WaitForSingleObject(thread, 1000) != 0) return 63;
	DWORD code = 1;
	if (!GetExitCodeThread(thread, &code) || code || !CloseHandle(thread)) return 64;
	if (!PeekMessageW(&message, NULL, 0, 0, PM_REMOVE) || message.message != WM_APP + 1) return 65;
	if (GetQueueStatus(QS_SENDMESSAGE)) return 66;
	if (!QueueUserAPC(completion, GetCurrentThread(), 23)) return 67;
	if (MsgWaitForMultipleObjectsEx(0, NULL, 0, QS_SENDMESSAGE, MWMO_ALERTABLE) != WAIT_IO_COMPLETION || apcs != 1) return 68;
	if (!DestroyWindow(target) || !UnregisterClassW(definition.lpszClassName, definition.hInstance)) return 69;
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_NCCREATE) return TRUE;
	return DefWindowProcW(window, message, wparam, lparam);
}

static DWORD WINAPI other_queue(void *unused)
{
	(void)unused;
	UINT size = 99;
	return GetRawInputBuffer(NULL, &size, sizeof(RAWINPUTHEADER)) || size ? 1 : 0;
}

/* Buffered input uses the native header on WOW64 as well as on x64. */
struct BufferedMouse {
	DWORD type, size;
	ULONGLONG device, wparam;
	RAWMOUSE mouse;
};

int raven_entry(void)
{
	WNDCLASSW definition = {0};
	definition.hInstance = GetModuleHandleW(NULL);
	definition.lpfnWndProc = procedure;
	definition.lpszClassName = L"RavenRawBuffer";
	if (!RegisterClassW(&definition)) return 1;
	HWND window = CreateWindowExW(0, definition.lpszClassName, L"raw", WS_POPUP | WS_VISIBLE, 0, 0, 32, 32,
		NULL, NULL, definition.hInstance, NULL);
	if (!window || !ValidateRect(window, NULL)) return 2;
	MSG message;
	while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {}
	UINT size = 99;
	if (GetRawInputBuffer(NULL, &size, sizeof(RAWINPUTHEADER)) || size) return 3;
	RAWINPUTDEVICE device = {1, 2, RIDEV_NOLEGACY, window};
	if (!RegisterRawInputDevices(&device, 1, sizeof(device)) || !SetWindowTextW(window, L"raw: ready")) return 4;
	if (!PeekMessageW(&message, NULL, WM_INPUT, WM_INPUT, PM_NOREMOVE) || message.message != WM_INPUT) return 5;
	const HRAWINPUT first = (HRAWINPUT)message.lParam;
	size = 0;
	if (GetRawInputBuffer(NULL, &size, sizeof(RAWINPUTHEADER)) || !size || size > 1024) return 6;
	if (!(HIWORD(GetQueueStatus(QS_RAWINPUT)) & QS_RAWINPUT)) return 7;
	_Alignas(8) BYTE storage[256];
	for (UINT i = 0; i < sizeof(storage); ++i) storage[i] = 0x5a;
	size = sizeof(storage);
	if (GetRawInputBuffer((PRAWINPUT)storage, &size, sizeof(RAWINPUTHEADER) - 1) != (UINT)-1 ||
		GetLastError() != ERROR_INVALID_PARAMETER || storage[0] != 0x5a) return 8;
	size = 0;
	if (GetRawInputBuffer((PRAWINPUT)storage, &size, sizeof(RAWINPUTHEADER)) != (UINT)-1 ||
		GetLastError() != ERROR_INSUFFICIENT_BUFFER || size < sizeof(struct BufferedMouse) || storage[0] != 0x5a) return 9;
	BYTE *protected = VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	DWORD previous;
	if (!protected || !VirtualProtect(protected, 4096, PAGE_READONLY, &previous)) return 10;
	size = 4096;
	if (GetRawInputBuffer((PRAWINPUT)protected, &size, sizeof(RAWINPUTHEADER)) != (UINT)-1 || GetLastError() != ERROR_NOACCESS) return 11;
	if (!VirtualFree(protected, 0, MEM_RELEASE)) return 12;
	HANDLE thread = CreateThread(NULL, 0, other_queue, NULL, 0, NULL);
	DWORD code = 1;
	if (!thread || WaitForSingleObject(thread, 1000) || !GetExitCodeThread(thread, &code) || code || !CloseHandle(thread)) return 13;
	if (!PeekMessageW(&message, NULL, WM_INPUT, WM_INPUT, PM_REMOVE) || (HRAWINPUT)message.lParam != first) return 14;
	RAWINPUT single;
	size = sizeof(single);
	if (GetRawInputData(first, RID_INPUT, &single, &size, sizeof(RAWINPUTHEADER)) != sizeof(single) ||
		single.header.dwType != RIM_TYPEMOUSE || single.data.mouse.lLastX != 5 || single.data.mouse.lLastY != -3) return 15;
	if (!PostMessageW(window, WM_APP + 1, 17, 19)) return 16;
	size = sizeof(struct BufferedMouse);
	if (GetRawInputBuffer((PRAWINPUT)storage, &size, sizeof(RAWINPUTHEADER)) != 1) return 17;
	struct BufferedMouse *raw = (struct BufferedMouse *)storage;
	if (raw->type != RIM_TYPEMOUSE || raw->size != sizeof(*raw) || raw->device != 1 || raw->wparam ||
		raw->mouse.usButtonFlags != RI_MOUSE_LEFT_BUTTON_DOWN || raw->mouse.lLastX || raw->mouse.lLastY) return 18;
	size = sizeof(struct BufferedMouse) * 2;
	if (GetRawInputBuffer((PRAWINPUT)storage, &size, sizeof(RAWINPUTHEADER)) != 2 ||
		raw[0].mouse.usButtonFlags != RI_MOUSE_LEFT_BUTTON_UP || raw[1].mouse.usButtonFlags != RI_MOUSE_WHEEL ||
		(SHORT)raw[1].mouse.usButtonData != 120) return 19;
	if (!(HIWORD(GetQueueStatus(QS_RAWINPUT)) & QS_RAWINPUT)) return 20;
	size = sizeof(storage);
	if (GetRawInputBuffer((PRAWINPUT)storage, &size, sizeof(RAWINPUTHEADER)) != 1 || raw->mouse.lLastX != 7 || raw->mouse.lLastY != 9) return 21;
	if (HIWORD(GetQueueStatus(QS_RAWINPUT)) || PeekMessageW(&message, NULL, WM_INPUT, WM_INPUT, PM_REMOVE)) return 22;
	size = sizeof(storage);
	if (GetRawInputBuffer((PRAWINPUT)storage, &size, sizeof(RAWINPUTHEADER))) return 23;
	if (!PeekMessageW(&message, NULL, WM_APP + 1, WM_APP + 1, PM_REMOVE) || message.wParam != 17 || message.lParam != 19) return 24;
	if (!DestroyWindow(window) || !UnregisterClassW(definition.lpszClassName, definition.hInstance)) return 25;
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// One window with the controls programs use most, drawn by the runtime; the same source is built for 32 and 64 bits so that what the two
// runtimes draw can be compared pixel for pixel.
static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_DESTROY) {
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

int raven_entry(void)
{
	const HINSTANCE instance = GetModuleHandleW(NULL);
	WNDCLASSW class_info = {0};
	class_info.lpfnWndProc = procedure;
	class_info.hInstance = instance;
	class_info.lpszClassName = L"ControlsProbe";
	class_info.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
	class_info.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
	if (!RegisterClassW(&class_info))
		return 1;
	const HWND window = CreateWindowExW(0, L"ControlsProbe", L"Controls", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 40, 40, 420, 260, NULL, NULL, instance, NULL);
	if (!window)
		return 2;
	CreateWindowExW(0, L"STATIC", L"Static label", WS_CHILD | WS_VISIBLE, 10, 10, 200, 20, window, (HMENU)1, instance, NULL);
	CreateWindowExW(0, L"BUTTON", L"Push button", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 10, 40, 120, 28, window, (HMENU)2, instance, NULL);
	CreateWindowExW(0, L"BUTTON", L"Check box", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 10, 80, 120, 20, window, (HMENU)3, instance, NULL);
	CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"Edit text", WS_CHILD | WS_VISIBLE, 10, 110, 200, 24, window, (HMENU)4, instance, NULL);
	CreateWindowExW(0, L"BUTTON", L"Group", WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 230, 10, 150, 80, window, (HMENU)5, instance, NULL);
	ShowWindow(window, SW_SHOW);
	UpdateWindow(window);
	const DWORD end = GetTickCount() + 30000;
	MSG message;
	while (GetTickCount() < end) {
		while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
			if (message.message == WM_QUIT)
				return 0;
			TranslateMessage(&message);
			DispatchMessageW(&message);
		}
		Sleep(20);
	}
	return 0;
}

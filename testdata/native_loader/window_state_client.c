#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Window state read back right after it changes, including from inside the messages the change sends, whether the runtime or the
   program answers the reads. */

static int size_seen, size_failed;

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_SIZE) {
		RECT client;
		++size_seen;
		if (!GetClientRect(window, &client) || client.left || client.top || client.right != LOWORD(lparam) || client.bottom != HIWORD(lparam))
			size_failed = 1;
		if (GetWindowLongPtrW(window, GWLP_USERDATA) != 0x1234 && GetWindowLongPtrW(window, GWLP_USERDATA) != 0)
			size_failed = 1;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

int raven_entry(void)
{
	WNDCLASSW type = {0};
	type.lpfnWndProc = procedure;
	type.hInstance = GetModuleHandleW(NULL);
	type.lpszClassName = L"RavenWindowState";
	type.cbWndExtra = 16;
	if (!RegisterClassW(&type))
		return 1;
	HWND window = CreateWindowExW(0, L"RavenWindowState", L"state", WS_OVERLAPPEDWINDOW, 10, 20, 300, 200, NULL, NULL, type.hInstance, NULL);
	if (!window || !IsWindow(window) || !IsWindowUnicode(window))
		return 2;
	if (GetWindowLongPtrW(window, GWLP_WNDPROC) != (LONG_PTR)procedure || GetWindowLongPtrW(window, GWLP_HINSTANCE) != (LONG_PTR)type.hInstance)
		return 3;
	/* Every read follows the write before it. */
	for (LONG_PTR value = 1; value < 40; ++value) {
		SetWindowLongPtrW(window, GWLP_USERDATA, value);
		SetWindowLongPtrW(window, 8, value * 3);
		SetWindowLongW(window, 4, (LONG)value * 5);
		if (GetWindowLongPtrW(window, GWLP_USERDATA) != value || GetWindowLongPtrW(window, 8) != value * 3 || GetWindowLongW(window, 4) != value * 5 ||
			GetWindowLongW(window, -21) != (LONG)value)
			return 4;
	}
	SetWindowLongPtrW(window, GWLP_USERDATA, 0x1234);
	/* Indexes past the extra bytes fail as before. */
	SetLastError(0);
	if (GetWindowLongPtrW(window, 12) != 0 || GetLastError() != ERROR_INVALID_INDEX)
		return 5;
	if ((GetWindowLongW(window, GWL_STYLE) & WS_OVERLAPPEDWINDOW) != WS_OVERLAPPEDWINDOW)
		return 6;
	SetWindowLongW(window, GWL_STYLE, GetWindowLongW(window, GWL_STYLE) | WS_CLIPCHILDREN);
	if (!(GetWindowLongW(window, GWL_STYLE) & WS_CLIPCHILDREN))
		return 7;
	/* Properties named by an atom, set and removed. */
	if (GetPropW(window, (LPCWSTR)(ULONG_PTR)0xc123) || !SetPropW(window, (LPCWSTR)(ULONG_PTR)0xc123, (HANDLE)0x55))
		return 8;
	if (GetPropW(window, (LPCWSTR)(ULONG_PTR)0xc123) != (HANDLE)0x55 || GetPropW(window, (LPCWSTR)(ULONG_PTR)0xc124))
		return 9;
	RemovePropW(window, (LPCWSTR)(ULONG_PTR)0xc123);
	if (GetPropW(window, (LPCWSTR)(ULONG_PTR)0xc123))
		return 10;
	/* Rectangles after a move, and inside the size message the move sends. */
	size_seen = 0;
	if (!MoveWindow(window, 30, 40, 420, 330, TRUE) || !size_seen || size_failed)
		return 11;
	RECT outer, client;
	if (!GetWindowRect(window, &outer) || outer.left != 30 || outer.top != 40 || outer.right != 450 || outer.bottom != 370)
		return 12;
	if (!GetClientRect(window, &client) || client.right <= 0 || client.right > 420 || client.bottom <= 0 || client.bottom > 330)
		return 13;
	if (!DestroyWindow(window) || IsWindow(window) || GetWindowLongPtrW(window, GWLP_USERDATA) || GetLastError() != ERROR_INVALID_WINDOW_HANDLE)
		return 14;
	return 0;
}

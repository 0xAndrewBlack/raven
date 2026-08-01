/* Window that records, for every key it receives, the wall clock time at which the key reached its window procedure. The times are
 * appended to C:\latency.bin as 64-bit FILETIME values; C:\latency.txt holds READY once the window is shown. The program ends after
 * thirty keys or after a minute. */
#include <windows.h>

static int received;

static LRESULT CALLBACK procedure(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	if (message == WM_CHAR) {
		FILETIME now;
		GetSystemTimePreciseAsFileTime(&now);
		HANDLE f = CreateFileW(L"C:\\latency.bin", FILE_APPEND_DATA, 0, NULL, OPEN_ALWAYS, 0, NULL);
		DWORD n;
		WriteFile(f, &now, sizeof now, &n, NULL);
		unsigned long long character = (unsigned long long)wparam;
		WriteFile(f, &character, sizeof character, &n, NULL);
		CloseHandle(f);
		if (++received >= 30)
			PostQuitMessage(0);
		return 0;
	}
	if (message == WM_DESTROY) {
		PostQuitMessage(0);
		return 0;
	}
	return DefWindowProcW(window, message, wparam, lparam);
}

void __stdcall entry(void)
{
	HINSTANCE instance = GetModuleHandleW(NULL);
	WNDCLASSEXW class_info = {sizeof class_info, 0, procedure, 0, 0, instance, NULL, LoadCursorW(NULL, (LPCWSTR)IDC_ARROW), (HBRUSH)(COLOR_WINDOW + 1), NULL, L"RavenLatency", NULL};
	RegisterClassExW(&class_info);
	HWND window = CreateWindowExW(0, L"RavenLatency", L"Key latency", WS_OVERLAPPEDWINDOW | WS_VISIBLE, 100, 100, 320, 200, NULL, NULL, instance, NULL);
	if (!window)
		ExitProcess(1);
	ShowWindow(window, SW_SHOW);
	UpdateWindow(window);
	SetFocus(window);
	HANDLE f = CreateFileW(L"C:\\latency.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
	DWORD n;
	WriteFile(f, "READY", 5, &n, NULL);
	CloseHandle(f);
	const DWORD end = GetTickCount() + 60000;
	MSG message;
	while (GetTickCount() < end) {
		while (PeekMessageW(&message, NULL, 0, 0, PM_REMOVE)) {
			if (message.message == WM_QUIT)
				ExitProcess(0);
			TranslateMessage(&message);
			DispatchMessageW(&message);
		}
		Sleep(1);
	}
	ExitProcess(0);
}

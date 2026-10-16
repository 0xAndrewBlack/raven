#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <uxtheme.h>

/* Services that depend on their arguments alone, whether the runtime or the program answers them. */

LPWSTR WINAPI PathFindFileNameW(LPCWSTR path);

static LRESULT CALLBACK echo(HWND window, UINT message, WPARAM wparam, LPARAM lparam)
{
	return (LRESULT)window + message * 3 + (LRESULT)wparam * 5 + lparam * 7;
}

static int rect_is(const RECT *rect, LONG left, LONG top, LONG right, LONG bottom)
{
	return rect->left == left && rect->top == top && rect->right == right && rect->bottom == bottom;
}

int raven_entry(void)
{
	static const int cases[][4] = {{5, 3, 2, 8}, {-5, 3, 2, -8}, {5, -3, 2, -8}, {5, 3, -2, -8}, {-5, -3, -2, -8}, {96, 10, 72, 13},
		{-1, 1, 2, -1}, {1, 1, 0, -1}, {0x7fffffff, 2, 1, -1}, {0x7fffffff, 2, 2, 0x7fffffff}, {-0x7fffffff - 1, 1, 1, -0x7fffffff - 1},
		{0, 5, 7, 0}, {7, 1, 3, 2}, {8, 1, 3, 3}};
	for (unsigned index = 0; index < sizeof cases / sizeof cases[0]; ++index)
		if (MulDiv(cases[index][0], cases[index][1], cases[index][2]) != cases[index][3])
			return 1 + (int)index;
	RECT first, second, result;
	if (!SetRect(&first, 1, 2, 30, 40) || !rect_is(&first, 1, 2, 30, 40))
		return 20;
	if (!OffsetRect(&first, -1, 5) || !rect_is(&first, 0, 7, 29, 45))
		return 21;
	SetRect(&second, 10, 0, 50, 20);
	if (!IntersectRect(&result, &first, &second) || !rect_is(&result, 10, 7, 29, 20))
		return 22;
	SetRect(&second, 29, 0, 50, 20);
	if (IntersectRect(&result, &first, &second) || !rect_is(&result, 0, 0, 0, 0))
		return 23;
	SetRect(&second, 5, 5, 5, 60);
	if (IntersectRect(&result, &first, &second) || !rect_is(&result, 0, 0, 0, 0))
		return 24;
	SetRect(&second, 5, 5, 15, 60);
	if (!IntersectRect(&first, &first, &second) || !rect_is(&first, 5, 7, 15, 45))
		return 25;
	static const struct { const WCHAR *path; unsigned skip; } names[] = {{L"C:\\dir\\file.txt", 7}, {L"a/b", 2}, {L"C:file", 2},
		{L"file", 0}, {L"dir\\", 0}, {L"ab:c", 3}, {L"\\\\server\\share\\x", 15}, {L"", 0}, {L"C:", 0}, {L"C:\\", 0}};
	for (unsigned index = 0; index < sizeof names / sizeof names[0]; ++index)
		if (PathFindFileNameW(names[index].path) != names[index].path + names[index].skip)
			return 30 + (int)index;
	if (GetWindowTheme(NULL) || GetWindowTheme((HWND)0x12345))
		return 40;
	if (CallWindowProcW(echo, (HWND)11, 13, 17, 19) != 11 + 13 * 3 + 17 * 5 + 19 * 7 || CallWindowProcA(echo, (HWND)1, 2, 3, 4) != 1 + 6 + 15 + 28)
		return 41;
	SetLastError(0);
	if (CallWindowProcW(NULL, (HWND)1, 2, 3, 4) || GetLastError() != ERROR_INVALID_PARAMETER)
		return 42;
	HDC screen = GetDC(NULL);
	if (GetSystemMetrics(SM_CXVSCROLL) != 17 || GetSystemMetrics(SM_CXICON) != 32 || GetSystemMetrics(SM_CMOUSEBUTTONS) != 3 ||
		GetSystemMetrics(200) != 0 || GetSystemMetrics(SM_CXSCREEN) != GetDeviceCaps(screen, HORZRES) || GetSystemMetrics(-1) != 0)
		return 43;
	ReleaseDC(NULL, screen);
	LOGBRUSH brush;
	if (GetObjectW(GetSysColorBrush(COLOR_WINDOW), sizeof brush, &brush) != sizeof brush || brush.lbColor != GetSysColor(COLOR_WINDOW) ||
		GetSysColor(500) != 0)
		return 44;
	return 0;
}

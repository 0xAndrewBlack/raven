#include <windows.h>
#include <commctrl.h>
#include <uxtheme.h>

/* Side-by-side classes and visual styles as a program with the common controls 6 manifest sees them: its buttons are the version 6
   class under their plain name, contexts made from a manifest file activate and deactivate, and the default button of the visual style
   is drawn in the accent color. */

#ifndef ICC_STANDARD_CLASSES
#define ICC_STANDARD_CLASSES 0x4000
#endif
/* The push button part and its default state, from the visual styles' part and state tables. */
#define BP_PUSHBUTTON 1
#define PBS_DEFAULTED 5
#ifndef BCM_GETIDEALSIZE
#define BCM_GETIDEALSIZE 0x1601
#endif

int raven_entry(void)
{
	INITCOMMONCONTROLSEX classes = {sizeof classes, ICC_STANDARD_CLASSES | ICC_WIN95_CLASSES};
	WCHAR name[64], path[MAX_PATH];
	if (!InitCommonControlsEx(&classes))
		return 1;
	HWND button = CreateWindowExW(0, L"Button", L"OK", WS_POPUP | BS_PUSHBUTTON, 0, 0, 80, 24, NULL, NULL, GetModuleHandleW(NULL), NULL);
	if (!button)
		return 2;
	if (!GetClassNameW(button, name, 64) || lstrcmpW(name, L"Button"))
		return 3;
	SIZE ideal = {0, 0};
	if (!SendMessageW(button, BCM_GETIDEALSIZE, 0, (LPARAM)&ideal))
		return 4;
	DestroyWindow(button);

	GetModuleFileNameW(NULL, path, MAX_PATH);
	for (WCHAR *at = path + lstrlenW(path); at > path; --at)
		if (at[-1] == L'\\') {
			lstrcpyW(at, L"actctx.manifest");
			break;
		}
	ACTCTXW request = {sizeof request};
	request.lpSource = path;
	HANDLE context = CreateActCtxW(&request);
	if (context == INVALID_HANDLE_VALUE)
		return 5;
	ULONG_PTR cookie = 0;
	HANDLE current = NULL;
	if (!ActivateActCtx(context, &cookie) || !cookie || !GetCurrentActCtx(&current) || current != context)
		return 6;
	ReleaseActCtx(current);
	if (!DeactivateActCtx(0, cookie))
		return 7;
	ReleaseActCtx(context);

	if (!IsThemeActive())
		return 8;
	HWND owner = CreateWindowExW(0, L"Button", L"", WS_POPUP, 0, 0, 10, 10, NULL, NULL, GetModuleHandleW(NULL), NULL);
	HTHEME theme = OpenThemeData(owner, L"Button");
	if (!theme)
		return 9;
	BITMAPINFO info = {{sizeof(BITMAPINFOHEADER), 40, -20, 1, 32, BI_RGB}};
	void *bits = NULL;
	HDC dc = CreateCompatibleDC(NULL);
	HBITMAP bitmap = CreateDIBSection(dc, &info, DIB_RGB_COLORS, &bits, NULL, 0);
	if (!bitmap || !bits)
		return 10;
	SelectObject(dc, bitmap);
	RECT whole = {0, 0, 40, 20};
	if (DrawThemeBackground(theme, dc, BP_PUSHBUTTON, PBS_DEFAULTED, &whole, NULL) != S_OK)
		return 11;
	const BYTE *center = (const BYTE *)bits + (10 * 40 + 20) * 4;
	if (center[0] != 0xb8 || center[1] != 0x5f || center[2] != 0x00)
		return 12;
	CloseThemeData(theme);
	DestroyWindow(owner);
	return 0;
}

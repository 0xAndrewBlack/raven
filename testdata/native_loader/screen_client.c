#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* The screen context GetDC(NULL) hands out, whether the runtime or the program answers it. A context the runtime makes is always a new
   one, so taking and releasing twice in a row and getting the same handle back shows the program answered both. */

static int screen_caps_hold(HDC dc)
{
	return GetDeviceCaps(dc, LOGPIXELSX) == 96 && GetDeviceCaps(dc, LOGPIXELSY) == 96 && GetDeviceCaps(dc, BITSPIXEL) == 32 &&
		GetDeviceCaps(dc, HORZRES) == GetSystemMetrics(SM_CXSCREEN) && GetDeviceCaps(dc, VERTRES) == GetSystemMetrics(SM_CYSCREEN) &&
		GetDeviceCaps(dc, TECHNOLOGY) == DT_RASDISPLAY;
}

int raven_entry(void)
{
	HDC first = GetDC(NULL);
	if (!first || !screen_caps_hold(first) || ReleaseDC(NULL, first) != 1)
		return 1;
	HDC again = GetDC(NULL);
	if (!again || !screen_caps_hold(again) || ReleaseDC(NULL, again) != 1)
		return 2;
	HDC third = GetDC(NULL);
	if (third != again || ReleaseDC(NULL, third) != 1)
		return 3;
	/* A context somebody holds is not handed out twice. */
	HDC held = GetDC(NULL), other = GetDC(NULL);
	if (!held || !other || held == other || !screen_caps_hold(other))
		return 4;
	if (ReleaseDC(NULL, held) != 1 || ReleaseDC(NULL, other) != 1)
		return 5;
	/* A context whose state a call changed is released by the runtime, and the next one starts clean. */
	HFONT font = CreateFontW(-30, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET, 0, 0, 0, 0, L"Arial");
	HDC changed = GetDC(NULL);
	if (!changed || !SelectObject(changed, font) || ReleaseDC(NULL, changed) != 1)
		return 6;
	HDC clean = GetDC(NULL);
	if (!clean || GetCurrentObject(clean, OBJ_FONT) == font || ReleaseDC(NULL, clean) != 1)
		return 6;
	DeleteObject(font);
	/* A memory context still answers for its own bitmap. */
	HDC memory = CreateCompatibleDC(NULL);
	if (!memory || GetDeviceCaps(memory, TECHNOLOGY) == DT_RASDISPLAY || !DeleteDC(memory))
		return 7;
	return 0;
}

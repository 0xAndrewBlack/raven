#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Icons, memory contexts and bitmaps released, whether the runtime or the program answers, and released only once. */

int raven_entry(void)
{
	HDC screen = GetDC(NULL);
	for (int round = 0; round < 4; ++round) {
		HBITMAP color = CreateCompatibleBitmap(screen, 16, 16), mask = CreateBitmap(16, 16, 1, 1, NULL);
		ICONINFO info = {TRUE, 0, 0, mask, color};
		HICON icon = CreateIconIndirect(&info);
		if (!color || !mask || !icon)
			return 1;
		/* The sequence an image list goes through: a context with the bitmap selected, released before the bitmap. */
		HDC memory = CreateCompatibleDC(screen);
		HGDIOBJ previous = SelectObject(memory, color);
		if (!memory || !previous || GetBkColor(memory) != RGB(255, 255, 255))
			return 2;
		if (DeleteObject(color))
			return 3;
		if (!DeleteDC(memory) || DeleteDC(memory) || GetBkColor(memory) != CLR_INVALID)
			return 4;
		if (!DeleteObject(color) || DeleteObject(color))
			return 5;
		if (!DeleteObject(mask) || DeleteObject(mask))
			return 6;
		if (!DestroyIcon(icon) || DestroyIcon(icon))
			return 7;
		BITMAP bitmap;
		if (GetObjectW(color, sizeof bitmap, &bitmap) || GetObjectW(mask, sizeof bitmap, &bitmap))
			return 8;
	}
	/* A DIB section released by the program is gone for the runtime as well. */
	BITMAPINFO header = {{sizeof header.bmiHeader, 8, 8, 1, 32}};
	void *bits = NULL;
	HBITMAP section = CreateDIBSection(screen, &header, DIB_RGB_COLORS, &bits, NULL, 0);
	if (!section || !bits || !DeleteObject(section) || DeleteObject(section))
		return 9;
	/* Window contexts are not memory contexts. */
	if (DeleteDC(screen) || !ReleaseDC(NULL, screen))
		return 10;
	return 0;
}

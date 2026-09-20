#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* GetObject on bitmaps, whether the runtime or the program answers it: sizes, the BITMAP, a DIB section's DIBSECTION and deleted
   bitmaps. */

int raven_entry(void)
{
	HDC screen = CreateCompatibleDC(NULL);
	BITMAPINFO info = {0};
	info.bmiHeader.biSize = sizeof info.bmiHeader;
	info.bmiHeader.biWidth = 30;
	info.bmiHeader.biHeight = -20;
	info.bmiHeader.biPlanes = 1;
	info.bmiHeader.biBitCount = 32;
	void *bits = NULL;
	HBITMAP section = CreateDIBSection(screen, &info, DIB_RGB_COLORS, &bits, NULL, 0);
	HBITMAP plain = CreateCompatibleBitmap(screen, 17, 9);
	if (!screen || !section || !bits || !plain)
		return 1;
	for (int round = 0; round < 3; ++round) {
		BITMAP bitmap;
		if (GetObjectW(plain, 0, NULL) != sizeof bitmap || GetObjectW(plain, sizeof bitmap, &bitmap) != sizeof bitmap ||
			bitmap.bmWidth != 17 || bitmap.bmHeight != 9 || bitmap.bmPlanes != 1 || bitmap.bmBits)
			return 2;
		if (GetObjectW(section, sizeof bitmap, &bitmap) != sizeof bitmap || bitmap.bmWidth != 30 || bitmap.bmHeight != 20 ||
			bitmap.bmBitsPixel != 32 || bitmap.bmWidthBytes != 120 || bitmap.bmBits != bits)
			return 3;
		if (GetObjectA(section, sizeof bitmap, &bitmap) != sizeof bitmap || bitmap.bmBits != bits)
			return 4;
		if (GetObjectW(section, 31, &bitmap) != 0)
			return 5;
		DIBSECTION full;
		if (GetObjectW(section, sizeof full, &full) != sizeof full || full.dsBmih.biWidth != 30 || full.dsBm.bmBits != bits)
			return 6;
	}
	if (!DeleteObject(plain) || GetObjectW(plain, 0, NULL) != 0)
		return 7;
	if (!DeleteObject(section) || !DeleteDC(screen))
		return 8;
	return 0;
}

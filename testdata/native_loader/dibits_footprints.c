#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

static int measure(int source_size, int target_size, int vertical, int block)
{
	DWORD values[256], actual[256];
	for (int index = 0; index < source_size; ++index)
		values[index] = 0xffffffffU ^ (index >= block && index < block + 24 ? 1U << (index - block) : 0);
	HDC source = CreateCompatibleDC(NULL), target = CreateCompatibleDC(NULL);
	HBITMAP bitmap = NULL;
	BITMAPINFO info = {0};
	info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
	info.bmiHeader.biWidth = vertical ? 1 : target_size;
	info.bmiHeader.biHeight = vertical ? -target_size : -1;
	info.bmiHeader.biPlanes = 1;
	info.bmiHeader.biBitCount = 32;
	BITMAPINFO source_info = info;
	source_info.bmiHeader.biWidth = vertical ? 1 : source_size;
	source_info.bmiHeader.biHeight = vertical ? -source_size : -1;
	void *source_pixels = NULL;
	bitmap = CreateDIBSection(source, &source_info, DIB_RGB_COLORS, &source_pixels, NULL, 0);
	if (!bitmap || !source_pixels) return 0;
	memcpy(source_pixels, values, source_size * 4);
	DWORD *pixels = NULL;
	HBITMAP output = CreateDIBSection(target, &info, DIB_RGB_COLORS, (void **)&pixels, NULL, 0);
	if (!source || !target || !bitmap || !output || !pixels ||
		GetBitmapBits(bitmap, source_size * 4, actual) != source_size * 4)
		return 0;
	for (int index = 0; index < source_size; ++index)
		if (actual[index] != values[index])
			return 0;
	for (int index = 0; index < target_size; ++index)
		pixels[index] = 0;
	HGDIOBJ previous_source = SelectObject(source, bitmap), previous_target = SelectObject(target, output);
	if (!previous_source || !previous_target || !SetStretchBltMode(target, BLACKONWHITE) ||
		(StretchDIBits(target, 0, 0, info.bmiHeader.biWidth, -info.bmiHeader.biHeight, 0, 0, source_info.bmiHeader.biWidth, -source_info.bmiHeader.biHeight, source_pixels, &source_info, DIB_RGB_COLORS, SRCCOPY) <= 0) || !GdiFlush())
		return 0;
	printf("%d,%d,%d,%d", source_size, target_size, vertical, block);
	for (int index = 0; index < target_size; ++index)
		printf(",%06lx", (~pixels[index]) & 0xffffffU);
	printf("\n");
	SelectObject(source, previous_source);
	SelectObject(target, previous_target);
	return DeleteObject(bitmap) && DeleteObject(output) && DeleteDC(source) && DeleteDC(target);
}

int main(void)
{
	for (int source = 1; source <= 256; ++source) {
		if (source > 40 && source != 48 && source != 64 && source != 128 && source != 256)
			continue;
		for (int target = 1; target <= 300; ++target) {
			if (target > 50 && target != 64 && target != 96 && target != 128 && target != 192 &&
				target != 200 && target != 255 && target != 256 && target != 300)
				continue;
			for (int vertical = 0; vertical < 2; ++vertical)
				for (int block = 0; block < source; block += 24)
					if (!measure(source, target, vertical, block))
						return 1;
		}
	}
	return 0;
}

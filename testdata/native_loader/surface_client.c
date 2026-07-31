#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "icon_data.h"

__declspec(dllexport) volatile unsigned phase;

int raven_entry(void)
{
	for (unsigned bottom = 0; bottom < 2; ++bottom) {
		BITMAPINFO info = {0};
		info.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		info.bmiHeader.biWidth = 4;
		info.bmiHeader.biHeight = bottom ? 2 : -2;
		info.bmiHeader.biPlanes = 1;
		info.bmiHeader.biBitCount = 32;
		BYTE *pixels = NULL;
		HDC dc = CreateCompatibleDC(NULL);
		HDC other = CreateCompatibleDC(dc);
		HBITMAP bitmap = CreateDIBSection(dc,&info,DIB_RGB_COLORS,(void **)&pixels,NULL,77);
		if (!dc || !other || !bitmap || !pixels)
			return 1;
		HGDIOBJ stock = SelectObject(dc,bitmap);
		if (!stock || SelectObject(dc,bitmap) != bitmap || SelectObject(other,bitmap) || SelectObject(other,stock) != stock)
			return 2;
		DIBSECTION section;
		if (GetObjectW(bitmap,sizeof(section),&section) != sizeof(section) || section.dsBm.bmBits != pixels ||
			section.dsBm.bmWidth != 4 || section.dsBm.bmHeight != 2 || section.dsBm.bmWidthBytes != 16 ||
			section.dsBmih.biHeight != 2 || section.dsBmih.biSizeImage != 32 || section.dshSection)
			return 3;
		for (unsigned p = 0; p < 8; ++p) {
			pixels[p*4] = 145;
			pixels[p*4+1] = 115;
			pixels[p*4+2] = 66;
			pixels[p*4+3] = 0;
		}
		HICON icon = CreateIconFromResourceEx((BYTE *)color_icon,sizeof(color_icon),TRUE,0x30000,0,0,0);
		if (!icon || !DrawIconEx(dc,1,0,icon,0,0,0,NULL,DI_NORMAL))
			return 4;
		static const BYTE expected[24] = {145,115,66,0,72,185,33,128,255,0,0,255,145,115,66,1,100,8,246,254,145,115,66,0};
		for (unsigned y = 0; y < 2; ++y)
			for (unsigned x = 0; x < 3; ++x)
				for (unsigned c = 0; c < 4; ++c)
					if (pixels[((bottom ? 1-y : y)*4+x+1)*4+c] != expected[(y*3+x)*4+c])
						return 5;
		BYTE copy[32];
		if (GetBitmapBits(bitmap,sizeof(copy),copy) != sizeof(copy))
			return 6;
		for (unsigned y = 0; y < 2; ++y)
			for (unsigned x = 0; x < 16; ++x)
				if (copy[y*16+x] != pixels[(bottom ? 1-y : y)*16+x])
					return 6;
		if (SelectObject(dc,stock) != bitmap || !DeleteObject(bitmap) || !DeleteDC(dc) || !DeleteDC(other) || !DestroyIcon(icon))
			return 7;
	}
	phase = 1;
	return 0;
}

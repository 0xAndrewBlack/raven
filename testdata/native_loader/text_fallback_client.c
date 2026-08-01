#include <windows.h>

// A character the bundled face lacks takes its width from a fallback face instead of the replacement glyph.
int raven_entry(void)
{
	HDC dc=CreateCompatibleDC(NULL);
	LOGFONTW definition={0};
	HFONT font,previous;
	SIZE missing_size={0},cross_size={0},plus_size={0};
	WCHAR missing=0xffff,cross=0x2715,plus=0xff0b;
	if (!dc) return 1;
	definition.lfHeight=-16;definition.lfWeight=400;
	definition.lfFaceName[0]='A';definition.lfFaceName[1]='r';definition.lfFaceName[2]='i';definition.lfFaceName[3]='a';definition.lfFaceName[4]='l';
	font=CreateFontIndirectW(&definition);
	previous=(HFONT)SelectObject(dc,font);
	if (!font || !previous) return 2;
	if (!GetTextExtentPoint32W(dc,&missing,1,&missing_size) || missing_size.cx<=0) return 3;
	if (!GetTextExtentPoint32W(dc,&cross,1,&cross_size) || cross_size.cx<=0 || cross_size.cx==missing_size.cx) return 4;
	if (!GetTextExtentPoint32W(dc,&plus,1,&plus_size) || plus_size.cx<=0 || plus_size.cx==missing_size.cx) return 5;
	SelectObject(dc,previous);DeleteObject(font);DeleteDC(dc);
	return 0;
}

#include <windows.h>
#include "layout_reference.h"
__declspec(dllimport) INT WINAPI RavenDrawTextExW(HDC,LPWSTR,INT,LPRECT,UINT,LPDRAWTEXTPARAMS);
__declspec(dllexport) DWORD component_pixels[72][128*64];
__declspec(dllexport) DWORD component_rows[72][16];
static const WCHAR *faces[]={L"Liberation Sans",L"Liberation Mono",L"Liberation Serif"};
static unsigned frame;
static unsigned hash(const void *data,unsigned count)
{
	const BYTE *bytes=data;unsigned value=2166136261U;for(unsigned i=0;i<count;++i)value=(value^bytes[i])*16777619U;return value;
}

int raven_entry(void)
{
	HDC dc=CreateCompatibleDC(0);BITMAPINFO bi={0};bi.bmiHeader.biSize=40;bi.bmiHeader.biWidth=128;bi.bmiHeader.biHeight=-64;bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;DWORD *pixels;
	HBITMAP bitmap=CreateDIBSection(dc,&bi,0,(void **)&pixels,0,0);HGDIOBJ old=SelectObject(dc,bitmap);if(!dc||!bitmap||!old)return 1;
	HRGN clip=CreateRectRgn(0,0,128,64),hole=CreateRectRgn(60,20,80,40),copy=CreateRectRgn(0,0,0,0);if(!clip||!hole||!copy||!CombineRgn(clip,clip,hole,RGN_DIFF)||!SelectClipRgn(dc,clip))return 2;
	SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(23,91,157));
	const UINT modes[]={DT_NOPREFIX|DT_WORDBREAK,DT_NOPREFIX|DT_WORDBREAK|DT_CENTER,DT_NOPREFIX|DT_WORDBREAK|DT_RIGHT,0};const int widths[]={30,70,120};
	for(unsigned family=0;family<3;++family)for(unsigned size=0;size<2;++size){LOGFONTW lf={0};lf.lfHeight=size?-16:-12;lf.lfWeight=400;lf.lfQuality=NONANTIALIASED_QUALITY;for(unsigned i=0;faces[family][i];++i)lf.lfFaceName[i]=faces[family][i];HFONT font=CreateFontIndirectW(&lf);HGDIOBJ previous=SelectObject(dc,font);if(!font||!previous)return 3;
		for(unsigned mode=0;mode<4;++mode)for(unsigned width=0;width<3;++width){
			for(unsigned i=0;i<128*64;++i)pixels[i]=0x000a1735;WCHAR normal[]=L"Raven native \x03a9\x00e9 text wraps across lines",prefix[]=L"&Raven && text";RECT rect={3,5,widths[width],57};DRAWTEXTPARAMS params={sizeof(params),4,0,0,0};SetLastError(71);
			int result=RavenDrawTextExW(dc,mode==3?prefix:normal,-1,&rect,modes[mode],&params);DWORD error=GetLastError();if(result<=0||!GdiFlush())return 4;
			POINT point={0};if(GetClipRgn(dc,copy)!=1||!EqualRgn(copy,clip)||!GetCurrentPositionEx(dc,&point))return 5;
			DWORD *row=component_rows[frame];row[0]=family;row[1]=size;row[2]=mode;row[3]=width;row[4]=result;row[5]=error;row[6]=rect.left;row[7]=rect.top;row[8]=rect.right;row[9]=rect.bottom;row[10]=params.uiLengthDrawn;row[11]=point.x;row[12]=point.y;
			for(unsigned i=0;i<128*64;++i)component_pixels[frame][i]=pixels[i];if(hash(component_pixels[frame],sizeof(component_pixels[frame]))!=layout_pixels_reference[frame] || hash(row,sizeof(component_rows[frame]))!=layout_rows_reference[frame])return 10;
			++frame;
		}
		if(SelectObject(dc,previous)!=font||!DeleteObject(font))return 6;
	}
	if(!SelectClipRgn(dc,0)||!DeleteObject(clip)||!DeleteObject(hole)||!DeleteObject(copy)||SelectObject(dc,old)!=bitmap||!DeleteObject(bitmap)||!DeleteDC(dc))return 7;
	return frame==72?0:8;
}

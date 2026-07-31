#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifdef VISIBLE_SURFACE
#include "icon_data.h"
static DWORD expected[300*212];
#endif

static DWORD pixels[320*240];
static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_NCCALCSIZE && !wparam) {
		RECT *rect=(RECT *)lparam;
		rect->left+=7; rect->top+=11; rect->right-=13; rect->bottom-=17;
		return 0;
	}
	return DefWindowProcW(window,message,wparam,lparam);
}

static int verify(HBITMAP bitmap,DWORD color)
{
	if (GetBitmapBits(bitmap,sizeof(pixels),pixels)!=sizeof(pixels)) return 1;
	for (unsigned y=0;y<240;++y) for (unsigned x=0;x<320;++x) {
		const DWORD expected=x>=7 && x<307 && y>=11 && y<223 ? color : 0x0000ff;
		if ((pixels[y*320+x]&0xffffff)!=expected) return 2;
	}
	return 0;
}

int raven_entry(void)
{
	WNDCLASSW definition={0};
	definition.lpfnWndProc=procedure;
	definition.hInstance=GetModuleHandleW(NULL);
	definition.lpszClassName=L"raven.outer.surface";
	if (!RegisterClassW(&definition)) return 1;
	HWND window=CreateWindowExW(0,definition.lpszClassName,L"outer surface",WS_POPUP,20,30,320,240,NULL,NULL,definition.hInstance,NULL);
	if (!window) return 2;
#ifdef VISIBLE_SURFACE
	ShowWindow(window,SW_SHOW);
#endif
	RECT client,outer;
	if (!GetClientRect(window,&client) || !GetWindowRect(window,&outer) ||
		client.right!=300 || client.bottom!=212 || outer.left!=20 || outer.top!=30 || outer.right!=340 || outer.bottom!=270) return 3;
	HDC frame=GetWindowDC(window),dc=GetDC(window),capture=CreateCompatibleDC(frame);
	if (!frame || !dc || !capture) return 4;
	BITMAPINFO info={0}; info.bmiHeader.biSize=40; info.bmiHeader.biWidth=320; info.bmiHeader.biHeight=-240;
	info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32;
	void *bits=NULL;
	HBITMAP bitmap=CreateDIBSection(frame,&info,DIB_RGB_COLORS,&bits,NULL,0);
	if (!bitmap) return 5;
	HGDIOBJ original=SelectObject(capture,bitmap);
	HBRUSH blue=CreateSolidBrush(RGB(0,0,255)),red=CreateSolidBrush(RGB(255,0,0)),green=CreateSolidBrush(RGB(0,255,0));
	RECT all={0,0,320,240};
	if (!FillRect(frame,&all,blue) || !FillRect(dc,&all,red) || !BitBlt(capture,0,0,320,240,frame,0,0,SRCCOPY) || verify(bitmap,0xff0000)) return 6;
	if (!BitBlt(capture,0,0,300,212,dc,0,0,SRCCOPY) || GetBitmapBits(bitmap,sizeof(pixels),pixels)!=sizeof(pixels)) return 7;
	for (unsigned y=0;y<212;++y) for (unsigned x=0;x<300;++x) if ((pixels[y*320+x]&0xffffff)!=0xff0000) return 8;
	if (!FillRect(capture,&all,green) || !BitBlt(dc,0,0,320,240,capture,0,0,SRCCOPY) ||
		!BitBlt(capture,0,0,320,240,frame,0,0,SRCCOPY) || verify(bitmap,0x00ff00)) return 9;
#ifdef VISIBLE_SURFACE
	HDC reference=CreateCompatibleDC(frame);
	info.bmiHeader.biWidth=300; info.bmiHeader.biHeight=-212;
	HBITMAP reference_bitmap=CreateDIBSection(frame,&info,DIB_RGB_COLORS,&bits,NULL,0);
	if (!reference || !reference_bitmap) return 12;
	HGDIOBJ reference_original=SelectObject(reference,reference_bitmap);
	LOGFONTW font_definition={0}; font_definition.lfHeight=-16; font_definition.lfWeight=400;
	font_definition.lfQuality=NONANTIALIASED_QUALITY;
	const WCHAR *face=L"Liberation Sans";
	for (unsigned i=0;face[i];++i) font_definition.lfFaceName[i]=face[i];
	HFONT font=CreateFontIndirectW(&font_definition);
	HICON icon=CreateIconFromResourceEx(png_icon,sizeof(png_icon),TRUE,0x30000,8,8,0);
	if (!font || !icon || !FillRect(reference,&all,green)) return 13;
	HGDIOBJ client_font=SelectObject(dc,font),reference_font=SelectObject(reference,font);
	if (!client_font || !reference_font || SetTextColor(dc,RGB(255,255,255))==CLR_INVALID ||
		SetTextColor(reference,RGB(255,255,255))==CLR_INVALID || !SetBkMode(dc,TRANSPARENT) || !SetBkMode(reference,TRANSPARENT) ||
		!TextOutW(dc,-3,0,L"Client origin",13) || !TextOutW(reference,-3,0,L"Client origin",13) ||
		!DrawIconEx(dc,299,211,icon,8,8,0,NULL,DI_NORMAL) || !DrawIconEx(reference,299,211,icon,8,8,0,NULL,DI_NORMAL)) return 14;
	if (!BitBlt(capture,0,0,320,240,frame,0,0,SRCCOPY) || GetBitmapBits(bitmap,sizeof(pixels),pixels)!=sizeof(pixels) ||
		GetBitmapBits(reference_bitmap,sizeof(expected),expected)!=sizeof(expected)) return 15;
#ifdef PAINT_SURFACE
	RECT first={10,20,30,40},second={280,190,300,212},hole={14,24,18,28},point={100,100,101,101};
	if (!ValidateRect(window,NULL) || !InvalidateRect(window,&first,FALSE) || !InvalidateRect(window,&second,FALSE) ||
		!ValidateRect(window,&hole)) return 21;
	PAINTSTRUCT paint;
	HDC paint_dc=BeginPaint(window,&paint);
	if (!paint_dc || paint.fErase || paint.rcPaint.left!=10 || paint.rcPaint.top!=20 ||
		paint.rcPaint.right!=300 || paint.rcPaint.bottom!=212 || !FillRect(paint_dc,&all,red) || !EndPaint(window,&paint)) return 22;
	if (GetUpdateRect(window,NULL,FALSE) || !FillRect(dc,&point,red)) return 23;
	for (unsigned y=0;y<212;++y) for (unsigned x=0;x<300;++x) {
		const BOOL dirty=(x>=10&&x<30&&y>=20&&y<40) || (x>=280&&y>=190);
		const BOOL excluded=x>=14&&x<18&&y>=24&&y<28;
		if ((dirty && !excluded) || (x==100 && y==100)) expected[y*300+x]=0xff0000;
	}
	if (!BitBlt(capture,0,0,320,240,frame,0,0,SRCCOPY) || GetBitmapBits(bitmap,sizeof(pixels),pixels)!=sizeof(pixels)) return 24;
#endif
	unsigned ink=0;
	for (unsigned y=0;y<240;++y) for (unsigned x=0;x<320;++x) {
		const DWORD color=x>=7 && x<307 && y>=11 && y<223 ? expected[(y-11)*300+x-7]&0xffffff : 0x0000ff;
		if ((pixels[y*320+x]&0xffffff)!=color) return 16;
		if (color==0xffffff) ++ink;
	}
	if (!ink) return 17;
	SelectObject(dc,client_font); SelectObject(reference,reference_font); SelectObject(reference,reference_original);
	if (!DeleteObject(font) || !DestroyIcon(icon) || !DeleteObject(reference_bitmap) || !DeleteDC(reference)) return 18;
#endif
	SelectObject(capture,original);
	if (!DeleteObject(bitmap) || !DeleteDC(capture) || !DeleteObject(blue) || !DeleteObject(red) || !DeleteObject(green)) return 10;
	if (!ReleaseDC(window,dc) || !ReleaseDC(window,frame)) return 11;
#ifdef INPUT_SURFACE
	MSG message;
	for (;;) {
		if (GetMessageW(&message,NULL,0,0)<=0) return 19;
		if (message.message==WM_MOUSEMOVE) {
			if (message.hwnd!=window || (short)LOWORD(message.lParam)!=12 || (short)HIWORD(message.lParam)!=13 ||
				message.pt.x!=39 || message.pt.y!=54) return 20;
			break;
		}
		DispatchMessageW(&message);
	}
#endif
	if (!DestroyWindow(window) || !UnregisterClassW(definition.lpszClassName,definition.hInstance)) return 11;
	return 0;
}

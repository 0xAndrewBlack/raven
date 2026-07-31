#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static unsigned mode,created,destroyed,failed;
static HWND observed;
static HDC early;
static HFONT font;
static DWORD pixels[320*240];

static void acquire(HWND window)
{
	early=GetDC(window);
	if (!early || !SelectObject(early,font) || !DeleteObject(font)) failed=1;
}

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	observed=window;
	if (message==WM_NCCREATE && mode==2) { acquire(window); return FALSE; }
	if (message==WM_NCCALCSIZE && !wparam) {
		acquire(window);
		RECT *rect=(RECT *)lparam;
		rect->left+=7; rect->top+=11; rect->right-=13; rect->bottom-=17;
		if (mode==3) rect->left=(-2147483647L-1);
		return 0;
	}
	if (message==WM_CREATE) { ++created; if (mode==1) return -1; }
	if (message==WM_NCDESTROY) ++destroyed;
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	WNDCLASSW definition={0}; definition.lpfnWndProc=procedure;
	definition.hInstance=GetModuleHandleW(NULL); definition.lpszClassName=L"raven.creation.dc";
	if (!RegisterClassW(&definition)) return 1;
	unsigned cases=3;
#ifdef RAVEN_DC_BOUNDARY
	++cases;
#endif
	for (mode=0;mode<cases;++mode) {
		created=destroyed=failed=0; early=NULL; observed=NULL;
		LOGFONTW font_definition={0}; font_definition.lfHeight=-16; font_definition.lfWeight=400;
		font=CreateFontIndirectW(&font_definition); if (!font) return 2;
		HWND window=CreateWindowExW(0,definition.lpszClassName,L"creation dc",WS_POPUP,20,30,320,240,NULL,NULL,definition.hInstance,NULL);
		if (mode==3 && GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 11;
		if (failed || !early || created!=(mode>=2 ? 0 : 1) || (mode==0 ? !window || destroyed : window || destroyed!=1)) return 3;
		if (window) {
			ShowWindow(window,SW_SHOW);
			HDC frame=GetWindowDC(window),copy=CreateCompatibleDC(frame);
			BITMAPINFO info={0}; info.bmiHeader.biSize=40; info.bmiHeader.biWidth=320; info.bmiHeader.biHeight=-240;
			info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32;
			void *bits=NULL; HBITMAP bitmap=CreateDIBSection(frame,&info,DIB_RGB_COLORS,&bits,NULL,0);
			if (!frame || !copy || !bitmap) return 4;
			HGDIOBJ original=SelectObject(copy,bitmap);
			HBRUSH blue=CreateSolidBrush(RGB(0,0,255)),red=CreateSolidBrush(RGB(255,0,0)); RECT all={0,0,320,240};
			if (!blue || !red || !FillRect(frame,&all,blue) || !FillRect(early,&all,red) || !BitBlt(copy,0,0,320,240,frame,0,0,SRCCOPY) ||
				GetBitmapBits(bitmap,sizeof(pixels),pixels)!=sizeof(pixels)) return 5;
			for (unsigned y=0;y<240;++y) for (unsigned x=0;x<320;++x)
				if ((pixels[y*320+x]&0xffffff)!=(x>=7&&x<307&&y>=11&&y<223?0xff0000:0x0000ff)) return 6;
			SelectObject(copy,original);
			if (!DeleteObject(bitmap) || !DeleteDC(copy) || !DeleteObject(blue) || !DeleteObject(red) || !ReleaseDC(window,frame) ||
				!DestroyWindow(window)) return 7;
		}
		if (destroyed!=1 || IsWindow(observed) || GetObjectW(font,0,NULL)!=sizeof(LOGFONTW)) return 8;
		SetLastError(71);
		if (ReleaseDC(observed,early) || GetLastError()!=71) return 9;
	}
	return UnregisterClassW(definition.lpszClassName,definition.hInstance)?0:10;
}

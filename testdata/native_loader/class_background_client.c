#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static unsigned paints,erases;
static HBRUSH mark;
static const WCHAR class_name[]=L"RavenClassBackground";

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_ERASEBKGND) ++erases;
	if (message==WM_PAINT) {
		PAINTSTRUCT paint;
		HDC dc=BeginPaint(window,&paint);
		if (!dc || paint.fErase) { PostQuitMessage(30); return 0; }
		RECT rect={4,4,12,12};
		if (!paints && !FillRect(dc,&rect,mark)) { PostQuitMessage(31); return 0; }
		if (!EndPaint(window,&paint)) { PostQuitMessage(32); return 0; }
		++paints;
		rect.left=6; rect.top=6; rect.right=10; rect.bottom=10;
		if (paints<3) {
			if (!InvalidateRect(window,&rect,paints==1)) PostQuitMessage(33);
		} else if (!SetWindowTextW(window,L"Background: ready")) PostQuitMessage(34);
		return 0;
	}
	if (message==WM_DESTROY) PostQuitMessage(0);
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	LOGBRUSH descriptor;
#ifdef RAVEN_CLASS_BACKGROUND_BOUNDARY
	RECT bounds={0,0,4,4};
	if (FillRect((HDC)0xdead,&bounds,GetStockObject(BLACK_BRUSH)) || GetLastError()!=ERROR_INVALID_HANDLE) return 44;
	HDC memory=CreateCompatibleDC(NULL);
	if (!memory || FillRect(memory,&bounds,(HBRUSH)32) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED || !DeleteDC(memory)) return 45;
	WNDCLASSW invalid={0}; invalid.hInstance=instance; invalid.lpfnWndProc=DefWindowProcW; invalid.lpszClassName=class_name;
	invalid.hbrBackground=(HBRUSH)GetStockObject(SYSTEM_FONT);
	if (RegisterClassW(&invalid) || GetLastError()!=ERROR_INVALID_HANDLE) return 40;
	invalid.hbrBackground=(HBRUSH)32;
	if (RegisterClassW(&invalid) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 41;
	HBRUSH retained=CreateSolidBrush(RGB(37,91,173)); invalid.hbrBackground=retained; invalid.style=CS_OWNDC;
	HBRUSH styled_background=CreateSolidBrush(RGB(5,6,7)); invalid.hbrBackground=styled_background;
	ATOM owndc=styled_background ? RegisterClassW(&invalid) : 0;
	if (!retained || !owndc || GetObjectW(retained,sizeof(descriptor),&descriptor)!=sizeof(descriptor) ||
		!UnregisterClassW(MAKEINTATOM(owndc),instance)) return 42;
	invalid.hbrBackground=retained; invalid.style=0;
	ATOM registered=RegisterClassW(&invalid);
	if (!registered || !UnregisterClassW(MAKEINTATOM(registered),instance) || GetObjectW(retained,sizeof(descriptor),&descriptor)) return 43;
	return 0;
#endif
	for (unsigned kind=0;kind<4;++kind) {
		HBRUSH background=kind==0 ? CreateSolidBrush(RGB(37,91,173)) : kind==1 ? GetStockObject(BLACK_BRUSH) : kind==2 ? GetStockObject(NULL_BRUSH) : NULL;
		WNDCLASSW definition={0}; definition.hInstance=instance; definition.lpfnWndProc=DefWindowProcW;
		definition.lpszClassName=class_name; definition.hbrBackground=background;
		ATOM atom=RegisterClassW(&definition);
		if (!atom) return 1;
		HWND window=CreateWindowExW(0,MAKEINTATOM(atom),L"memory",WS_POPUP,0,0,16,12,NULL,NULL,instance,NULL);
		if (!window) return 2;
		HDC dc=CreateCompatibleDC(NULL); BITMAPINFO info={0};
		info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER); info.bmiHeader.biWidth=32; info.bmiHeader.biHeight=-20;
		info.bmiHeader.biPlanes=1; info.bmiHeader.biBitCount=32;
		unsigned char *pixels=NULL;
		HBITMAP bitmap=CreateDIBSection(dc,&info,DIB_RGB_COLORS,(void **)&pixels,NULL,0);
		HGDIOBJ previous=SelectObject(dc,bitmap);
		if (!dc || !bitmap || !pixels || !previous) return 3;
		for (unsigned i=0;i<2560;++i) pixels[i]=119;
		if (SendMessageW(window,WM_ERASEBKGND,(WPARAM)dc,0)!=(kind<3)) return 4;
		for (unsigned i=0;i<2560;i+=4) {
			unsigned b=kind==0 ? 173 : kind==1 ? 0 : 119;
			unsigned g=kind==0 ? 91 : b,r=kind==0 ? 37 : b,a=kind<2 ? 0 : 119;
			if (pixels[i]!=b || pixels[i+1]!=g || pixels[i+2]!=r || pixels[i+3]!=a) return 5;
		}
		if (UnregisterClassW(MAKEINTATOM(atom),instance) || GetLastError()!=ERROR_CLASS_HAS_WINDOWS) return 6;
		if (kind<3 && GetObjectW(background,sizeof(descriptor),&descriptor)!=sizeof(descriptor)) return 7;
		if (!DestroyWindow(window)) return 8;
		if (!kind && !SelectObject(dc,background)) return 9;
		if (!UnregisterClassW(MAKEINTATOM(atom),instance)) return 10;
		if (kind<3 && GetObjectW(background,sizeof(descriptor),&descriptor)!=sizeof(descriptor)) return 11;
		if (SelectObject(dc,previous)!=bitmap || !DeleteObject(bitmap) || !DeleteDC(dc)) return 12;
		if (!kind && GetObjectW(background,sizeof(descriptor),&descriptor)) return 13;
		if ((kind==1 || kind==2) && GetObjectW(background,sizeof(descriptor),&descriptor)!=sizeof(descriptor)) return 14;
	}
	HBRUSH background=CreateSolidBrush(RGB(37,91,173)); mark=CreateSolidBrush(RGB(166,44,31));
	if (!background || !mark) return 15;
	WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition); definition.hInstance=instance;
	definition.lpfnWndProc=procedure; definition.lpszClassName=class_name; definition.hbrBackground=background;
	ATOM atom=RegisterClassExW(&definition);
	if (!atom) return 16;
	HWND window=CreateWindowExW(0,MAKEINTATOM(atom),L"Raven class background",WS_POPUP,0,0,32,24,NULL,NULL,instance,NULL);
	if (!window) return 17;
	ShowWindow(window,SW_SHOW);
	MSG message; BOOL got;
	while ((got=GetMessageW(&message,NULL,0,0))>0) { TranslateMessage(&message); DispatchMessageW(&message); }
	// Wine's presentation path can deliver one extra erase outside BeginPaint.
	if (got<0 || message.wParam || paints!=3 || (erases!=2 && erases!=3) || IsWindow(window)) return 18;
	if (!UnregisterClassW(MAKEINTATOM(atom),instance) || GetObjectW(background,sizeof(descriptor),&descriptor) || !DeleteObject(mark)) return 19;
	return 0;
}

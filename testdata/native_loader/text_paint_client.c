#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static HFONT fonts[3];
static unsigned painted,failed;

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if(message==WM_PAINT) {
		PAINTSTRUCT paint; HDC dc=BeginPaint(window,&paint);
		RECT client; if(!dc || !GetClientRect(window,&client) || !FillRect(dc,&client,GetStockObject(BLACK_BRUSH))) failed=1;
		for(unsigned i=0;i<3 && !failed;++i) {
			if(!SelectObject(dc,fonts[i]) || SetTextColor(dc,painted ? RGB(166,44,31) : RGB(12,53,100))==CLR_INVALID ||
				SetBkColor(dc,RGB(255,255,255))==CLR_INVALID || !TextOutW(dc,12,12+(int)i*24,L"Raven C++ native text",21)) failed=2;
		}
		if(!EndPaint(window,&paint)) failed=3;
		HDC lease=GetDC(window);
		if(!lease || !SelectObject(lease,fonts[0]) || SetTextColor(lease,RGB(12,53,100))==CLR_INVALID || !TextOutW(lease,12,84,L"GetDC text",10) || !ReleaseDC(window,lease)) failed=5;
		++painted;
		if(painted==1) {
			RECT rect={12,12,42,29}; if(!InvalidateRect(window,&rect,FALSE)) failed=4;
		} else if(!SetWindowTextW(window,L"Text: ready")) failed=4;
		return 0;
	}
	if(message==WM_DESTROY) { PostQuitMessage(0); return 0; }
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	const WCHAR *names[]={L"Liberation Sans",L"Liberation Mono",L"Liberation Serif"};
	for(unsigned i=0;i<3;++i) {
		LOGFONTW definition={0}; definition.lfHeight=-16; definition.lfWeight=400; definition.lfQuality=NONANTIALIASED_QUALITY;
		for(unsigned c=0;names[i][c];++c) definition.lfFaceName[c]=names[i][c];
		fonts[i]=CreateFontIndirectW(&definition); if(!fonts[i]) return 2;
	}
	WNDCLASSW definition={0}; definition.lpfnWndProc=procedure; definition.lpszClassName=L"RavenTextPaint";
	if(!RegisterClassW(&definition)) return 3;
	HWND window=CreateWindowExW(0,definition.lpszClassName,L"Raven native text",WS_POPUP,12,23,320,120,NULL,NULL,NULL,NULL);
	if(!window) return 4;
	ShowWindow(window,SW_SHOW);
	MSG message; int received;
	while((received=GetMessageW(&message,NULL,0,0))>0) { TranslateMessage(&message); DispatchMessageW(&message); }
	if(received<0 || !painted || failed) return 5;
	for(unsigned i=0;i<3;++i) if(!DeleteObject(fonts[i])) return 6;
	if(!UnregisterClassW(definition.lpszClassName,NULL)) return 7;
	return 0;
}

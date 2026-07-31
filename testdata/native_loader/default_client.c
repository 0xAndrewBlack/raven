#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static unsigned destroyed,custom,contexts;
static HWND context_owner;
static LPARAM context_position;
__declspec(dllexport) volatile unsigned phase;

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_CONTEXTMENU) { ++contexts; context_owner=(HWND)wparam; context_position=lparam; if (contexts==1) return 41; }
	if (message==WM_DESTROY) { ++destroyed; PostQuitMessage(23); }
	if (custom && message==WM_GETTEXTLENGTH) return 42;
	if (custom && message==WM_SETTEXT) return 1;
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition); definition.hInstance=instance;
	definition.lpfnWndProc=procedure; definition.lpszClassName=L"RavenDefaultContract";
	ATOM atom=RegisterClassExW(&definition);
	if (!atom) return 1;
	HWND window=CreateWindowExW(0,MAKEINTATOM(atom),L"initial",WS_POPUP,1,2,32,32,NULL,NULL,instance,NULL);
	if (!window) return 2;
	if (SendMessageW(window,WM_NCHITTEST,0,MAKELPARAM(2,3))!=HTCLIENT ||
		SendMessageW(window,WM_NCHITTEST,0,MAKELPARAM(-2,-3))!=HTNOWHERE) return 15;
	const UINT pointer_messages[]={WM_MOUSEMOVE,WM_LBUTTONDOWN,WM_LBUTTONUP,WM_RBUTTONDOWN,WM_RBUTTONUP,WM_MBUTTONDOWN,WM_MBUTTONUP};
	for (unsigned i=0;i<sizeof(pointer_messages)/sizeof(pointer_messages[0]);++i) {
		SetLastError(0x5555);
		if (SendMessageW(window,pointer_messages[i],MK_CONTROL|MK_LBUTTON,MAKELPARAM(-17,23)) || GetLastError()!=0x5555) return 16;
	}
	if (contexts!=1 || context_owner!=window || context_position!=MAKELPARAM(-16,25) ||
		SendMessageW(window,WM_CONTEXTMENU,(WPARAM)window,MAKELPARAM(-16,25)) || contexts!=2) return 17;
	WCHAR text[16];
	if (GetWindowTextLengthW(window)!=7 || GetWindowTextW(window,text,16)!=7 || text[0]!='i' || text[6]!='l' || text[7]) return 3;
	text[3]=0x7777;
	if (GetWindowTextW(window,text,3)!=2 || text[0]!='i' || text[1]!='n' || text[2] || text[3]!=0x7777) return 4;
	text[0]=0x7777;
	if (GetWindowTextW(window,text,0) || text[0]!=0x7777) return 5;
	if (!SetWindowTextW(window,L"changed") || SendMessageW(window,WM_GETTEXTLENGTH,0,0)!=7 || SendMessageW(window,WM_GETTEXT,16,(LPARAM)text)!=7 || text[0]!='c') return 6;
	custom=1;
	if (GetWindowTextLengthW(window)!=42 || !SetWindowTextW(window,L"ignored")) return 7;
	custom=0;
	if (GetWindowTextW(window,text,16)!=7 || text[0]!='c') return 8;
	if (!SetWindowTextW(window,NULL) || GetWindowTextLengthW(window)) return 9;
	text[0]=0x7777;
	if (GetWindowTextW(window,text,16) || text[0]) return 10;
	if (SendMessageW(window,WM_PAINT,0,0) || SendMessageW(window,WM_ERASEBKGND,0,0)) return 11;
	if (SendMessageW(window,WM_CLOSE,0,0) || IsWindow(window) || destroyed!=1) return 12;
	MSG message;
	if (GetMessageW(&message,NULL,0,0) || message.message!=WM_QUIT || message.wParam!=23) return 13;
	if (!UnregisterClassW(MAKEINTATOM(atom),instance)) return 14;
	phase=1;
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static unsigned events, failure, mode, depth;
static HWND current;
static HINSTANCE instance;
static const WCHAR name[]=L"RavenWindowContract";
__declspec(dllexport) volatile unsigned phase;

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (!IsWindow(window) || !IsWindowUnicode(window)) failure=1;
	if (message==WM_NCCREATE || message==WM_CREATE) {
		CREATESTRUCTW *create=(CREATESTRUCTW *)lparam;
		if (create->lpCreateParams!=(void *)0x12345678 || create->hInstance!=instance || create->hMenu || create->hwndParent ||
			create->x!=12 || create->y!=23 || create->cx!=40 || create->cy!=50 || (DWORD)create->style!=WS_POPUP || create->dwExStyle)
			failure=2;
		if (message==WM_NCCREATE) { current=window; events|=1; return mode==1 ? FALSE : TRUE; }
		events|=4;
		return mode==2 ? -1 : 0;
	}
	if (message==WM_NCCALCSIZE) { events|=2; return 0; }
	if (message==WM_DESTROY) { events|=8; return 0; }
	if (message==WM_NCDESTROY) { events|=16; return 0; }
	if (message==WM_USER+1) {
		if (depth++) failure=3;
		LRESULT nested=SendMessageW(window,WM_USER+2,wparam+1,lparam+2);
		--depth;
		return nested+3;
	}
	if (message==WM_USER+2) return (LRESULT)(wparam+(WPARAM)lparam);
	return 0;
}

int raven_entry(void)
{
	instance=GetModuleHandleW(NULL);
	WNDCLASSEXW definition={0};
	definition.cbSize=sizeof(definition); definition.lpfnWndProc=procedure;
	definition.hInstance=instance; definition.lpszClassName=name;
	ATOM atom=RegisterClassExW(&definition);
	if (!atom) return 1;
	SetLastError(71);
	if (RegisterClassExW(&definition) || GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) return 2;
	HWND window=CreateWindowExW(0,MAKEINTATOM(atom),L"Owned window",WS_POPUP,12,23,40,50,NULL,NULL,instance,(void *)0x12345678);
	if (!window || window!=current || failure || (events & 7)!=7) return 3;
	SetLastError(71);
	if (UnregisterClassW(name,instance) || GetLastError()!=ERROR_CLASS_HAS_WINDOWS) return 4;
	if (SendMessageW(window,WM_USER+1,0x1122334455667700ULL,0x101)!=0x1122334455667807ULL || failure || depth) return 5;
	if (!DestroyWindow(window) || IsWindow(window) || failure || (events & 31)!=31) return 6;
	phase=1;
	mode=1; events=0;
	if (CreateWindowExW(0,name,NULL,WS_POPUP,12,23,40,50,NULL,NULL,instance,(void *)0x12345678) || IsWindow(current)) return 7;
	if (events!=17 || failure) return 8;
	mode=2; events=0;
	if (CreateWindowExW(0,name,NULL,WS_POPUP,12,23,40,50,NULL,NULL,instance,(void *)0x12345678) || IsWindow(current)) return 9;
	if (events!=23 || failure) return 10;
	if (!UnregisterClassW(MAKEINTATOM(atom),instance)) return 11;
	SetLastError(71);
	if (SendMessageW(current,WM_USER+2,1,2) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE) return 12;
	SetLastError(71);
	if (DestroyWindow(current) || GetLastError()!=ERROR_ACCESS_DENIED) return 13;
	WNDCLASSW basic={0};
	basic.hInstance=instance; basic.lpfnWndProc=procedure; basic.lpszClassName=L"RavenBasicClass";
	ATOM basic_atom=RegisterClassW(&basic);
	if (!basic_atom || !UnregisterClassW(MAKEINTATOM(basic_atom),instance)) return 14;
	phase=2;
	return 0;
}

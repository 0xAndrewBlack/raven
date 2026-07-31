#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static unsigned delivered;
__declspec(dllexport) volatile unsigned phase;

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_NCCREATE) return TRUE;
	if (message==WM_APP+1) {
		++delivered;
		if (!PostMessageW(window,WM_APP+3,7,9)) return -1;
		return (LRESULT)(wparam+(ULONG_PTR)lparam);
	}
	if (message==WM_APP+3) { ++delivered; return 16; }
	(void)wparam; (void)lparam;
	return 0;
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition); definition.hInstance=instance;
	definition.lpfnWndProc=procedure; definition.lpszClassName=L"RavenMessageContract";
	ATOM atom=RegisterClassExW(&definition);
	if (!atom) return 1;
	HWND window=CreateWindowExW(0,MAKEINTATOM(atom),L"messages",WS_POPUP,1,2,32,32,NULL,NULL,instance,NULL);
	if (!window) return 2;
	MSG message;
	while (PeekMessageW(&message,NULL,0,0,PM_REMOVE)) {}
	if (!PostMessageW(window,WM_APP+1,(WPARAM)0x1234567800000000ULL,(LPARAM)0x22334455) || delivered) return 3;
	if (!PostMessageW(NULL,WM_APP+2,11,13)) return 4;
	if (PeekMessageW(&message,window,WM_APP+2,WM_APP+2,PM_REMOVE)) return 5;
	if (!PeekMessageW(&message,(HWND)-1,0,0,PM_NOREMOVE) || message.hwnd || message.message!=WM_APP+2 || message.wParam!=11 || message.lParam!=13) return 6;
	if (!PeekMessageW(&message,(HWND)-1,0,0,PM_REMOVE) || message.message!=WM_APP+2 || DispatchMessageW(&message) || TranslateMessage(&message)) return 7;
	if (PeekMessageW(&message,(HWND)-1,0,0,PM_REMOVE)) return 8;
	if (!PeekMessageW(&message,window,WM_APP+1,WM_APP+1,PM_NOREMOVE) || message.hwnd!=window || message.message!=WM_APP+1 || message.wParam!=(WPARAM)0x1234567800000000ULL || message.lParam!=0x22334455) return 9;
	if (GetMessageW(&message,window,WM_APP+1,WM_APP+1)!=1 || DispatchMessageW(&message)!=(LRESULT)0x1234567822334455ULL || delivered!=1) return 10;
	if (GetMessageW(&message,window,WM_APP+3,WM_APP+3)!=1 || DispatchMessageW(&message)!=16 || delivered!=2) return 11;
	PostQuitMessage(17); PostQuitMessage(23);
	if (!PostMessageW(NULL,WM_APP+2,19,21)) return 12;
	if (!PeekMessageW(&message,NULL,0,0,PM_REMOVE) || message.message!=WM_APP+2) return 13;
	if (!PeekMessageW(&message,window,WM_APP+1,WM_APP+1,PM_NOREMOVE) || message.message!=WM_QUIT || message.hwnd || message.wParam!=23) return 14;
	if (GetMessageW(&message,window,WM_APP+1,WM_APP+1) || message.message!=WM_QUIT || message.wParam!=23) return 15;
	if (PeekMessageW(&message,NULL,0,0,PM_REMOVE)) return 16;
	if (!DestroyWindow(window) || !UnregisterClassW(MAKEINTATOM(atom),instance)) return 17;
	SetLastError(0);
	if (PostMessageW(window,WM_APP,0,0) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE) return 18;
	SetLastError(0);
	if (GetMessageW(&message,window,0,0)!=-1 || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE) return 19;
	phase=1;
	return 0;
}

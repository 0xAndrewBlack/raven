#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static WNDPROC previous;
static unsigned created,nested;
__declspec(dllexport) volatile unsigned phase;

static LRESULT CALLBACK original(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_NCCREATE) {
		CREATESTRUCTW *creation=(CREATESTRUCTW *)lparam;
		if (GetWindowLongPtrW(window,GWLP_USERDATA) || GetWindowLongPtrW(window,0) ||
			GetClassLongPtrW(window,GCL_CBWNDEXTRA)!=32) return FALSE;
		SetLastError(0);
		if (SetWindowLongPtrW(window,GWLP_USERDATA,(LONG_PTR)creation->lpCreateParams) || GetLastError()) return FALSE;
		++created;
	}
	if (message==WM_APP+1) return 0x1111;
	if (message==WM_APP+2) { ++nested; return 0x200+(LRESULT)wparam-lparam; }
	return DefWindowProcW(window,message,wparam,lparam);
}

static LRESULT CALLBACK subclass(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_APP+1) return 0x100+SendMessageW(window,WM_APP+2,wparam,lparam);
	return CallWindowProcW(previous,window,message,wparam,lparam);
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition); definition.hInstance=instance;
	definition.lpfnWndProc=original; definition.lpszClassName=L"RavenWindowData";
	definition.cbClsExtra=32; definition.cbWndExtra=32;
#ifdef RAVEN_WINDOW_DATA_BOUNDARY
	definition.cbClsExtra=-1;
	if (RegisterClassExW(&definition) || GetLastError()!=ERROR_INVALID_PARAMETER) return 40;
	definition.cbClsExtra=4097;
	if (RegisterClassExW(&definition) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 41;
	definition.cbClsExtra=32;
#endif
	ATOM atom=RegisterClassExW(&definition);
	if (!atom) return 1;
	HWND a=CreateWindowExW(0,MAKEINTATOM(atom),L"first",WS_POPUP,0,0,32,24,NULL,NULL,instance,(void *)0x12345);
	HWND b=CreateWindowExW(0,MAKEINTATOM(atom),L"second",WS_POPUP,0,0,32,24,NULL,NULL,instance,NULL);
	if (!a || !b || created!=2 || GetWindowLongPtrW(a,GWLP_USERDATA)!=0x12345 || GetWindowLongPtrW(b,GWLP_USERDATA)) return 2;
#ifdef RAVEN_WINDOW_DATA_BOUNDARY
	SetLastError(0);
	if (!GetWindowLongPtrA(a,GWLP_WNDPROC) || GetLastError() || !GetClassLongPtrA(a,GCLP_WNDPROC)) return 42;
	if (SetWindowLongPtrW(a,GWL_STYLE,WS_CHILD)!=(WS_POPUP | WS_CLIPSIBLINGS) || GetWindowLongPtrW(a,GWL_STYLE)!=WS_CHILD) return 44;
	if (SetClassLongPtrW(a,GCL_CBWNDEXTRA,64)!=32 || GetClassLongPtrW(a,GCL_CBWNDEXTRA)!=64) return 45;
	if (!DestroyWindow(a) || !DestroyWindow(b) || !UnregisterClassW(MAKEINTATOM(atom),instance)) return 46;
	return 0;
#endif
	SetLastError(0x7777);
	if (GetWindowLongPtrW(a,24) || GetWindowLongW(a,28) || GetLastError()!=0x7777) return 3;
	if (SetWindowLongPtrW(a,0,(LONG_PTR)0x1122334455667788ULL) || GetLastError()!=0x7777 ||
		(ULONG_PTR)GetWindowLongPtrA(a,0)!=0x1122334455667788ULL || (DWORD)GetWindowLongA(a,0)!=0x55667788) return 4;
	if ((DWORD)SetWindowLongA(a,1,0x12345678)!=0x44556677 || (ULONG_PTR)GetWindowLongPtrW(a,0)!=0x1122331234567888ULL || GetWindowLongPtrW(b,0)) return 5;
	if (SetWindowLongPtrA(b,24,0x98765) || GetWindowLongW(b,24)!=0x98765 || GetLastError()!=0x7777) return 6;
	if (SetWindowLongW(b,28,0x1234) || (ULONG_PTR)GetWindowLongPtrW(b,24)!=0x0000123400098765ULL) return 7;
	if (GetWindowLongPtrW(a,25) || GetLastError()!=ERROR_INVALID_INDEX || SetWindowLongPtrW(a,25,0x999) || GetLastError()!=ERROR_INVALID_INDEX ||
		GetWindowLongW(a,29) || GetLastError()!=ERROR_INVALID_INDEX || SetWindowLongW(a,29,0x999) || GetLastError()!=ERROR_INVALID_INDEX ||
		(ULONG_PTR)GetWindowLongPtrW(a,0)!=0x1122331234567888ULL) return 8;
	SetLastError(0x7777);
	if (SetClassLongPtrW(a,0,(LONG_PTR)0x1122334455667788ULL) || GetLastError()!=0x7777 ||
		(ULONG_PTR)GetClassLongPtrA(b,0)!=0x1122334455667788ULL || GetClassLongA(b,0)!=0x55667788) return 9;
	if (SetClassLongA(b,1,0x12345678)!=0x44556677 || (ULONG_PTR)GetClassLongPtrW(a,0)!=0x1122331234567888ULL) return 10;
	if (SetClassLongPtrA(b,24,0x98765) || SetClassLongW(a,28,0x1234) || (ULONG_PTR)GetClassLongPtrW(b,24)!=0x0000123400098765ULL) return 11;
	if (GetClassLongPtrW(a,25) || GetLastError()!=ERROR_INVALID_INDEX || SetClassLongPtrW(a,25,0x999) || GetLastError()!=ERROR_INVALID_INDEX ||
		GetClassLongW(a,29) || GetLastError()!=ERROR_INVALID_INDEX || SetClassLongW(a,29,0x999) || GetLastError()!=ERROR_INVALID_INDEX) return 12;
	if (GetClassLongPtrW(a,GCW_ATOM)!=atom || GetClassLongW(a,GCL_CBCLSEXTRA)!=32 || GetClassLongPtrW(a,GCL_CBWNDEXTRA)!=32 ||
		GetClassLongPtrW(a,GCLP_HMODULE)!=(ULONG_PTR)instance || GetClassLongPtrW(a,GCLP_WNDPROC)!=(ULONG_PTR)original ||
		GetWindowLongPtrW(a,GWLP_HINSTANCE)!=(LONG_PTR)instance || GetWindowLongPtrW(a,GWL_STYLE)!=(WS_POPUP | WS_CLIPSIBLINGS) ||
		GetWindowLongPtrW(a,GWL_EXSTYLE) || GetWindowLongPtrW(a,GWLP_HWNDPARENT) || GetWindowLongPtrW(a,GWLP_ID)) return 13;
	if (GetWindowLongW(a,-6) || GetLastError()!=ERROR_INVALID_INDEX || GetWindowLongW(a,-4) || GetLastError()!=ERROR_INVALID_INDEX) return 14;
	if (SetWindowLongPtrW(a,GWLP_USERDATA,(LONG_PTR)0x1122334455667788ULL)!=0x12345 || (DWORD)GetWindowLongW(a,GWLP_USERDATA)!=0x55667788 ||
		(DWORD)SetWindowLongW(a,GWLP_USERDATA,(LONG)0x87654321)!=0x55667788 || (ULONG_PTR)GetWindowLongPtrW(a,GWLP_USERDATA)!=0xffffffff87654321ULL) return 15;
	if (SendMessageW(a,WM_APP+1,5,2)!=0x1111) return 16;
	previous=(WNDPROC)SetWindowLongPtrW(a,GWLP_WNDPROC,(LONG_PTR)subclass);
	if (previous!=original || GetWindowLongPtrW(a,GWLP_WNDPROC)!=(LONG_PTR)subclass ||
		GetClassLongPtrW(a,GCLP_WNDPROC)!=(ULONG_PTR)original || SendMessageW(a,WM_APP+1,5,2)!=0x303 || nested!=1 ||
		CallWindowProcW(previous,a,WM_APP+2,9,4)!=0x205 || nested!=2 || SendMessageW(b,WM_APP+1,5,2)!=0x1111) return 17;
	if (SetWindowLongPtrW(a,GWLP_WNDPROC,(LONG_PTR)previous)!=(LONG_PTR)subclass || SendMessageW(a,WM_APP+1,5,2)!=0x1111) return 18;
	if (!DestroyWindow(a) || GetWindowLongPtrW(a,0) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE || GetClassLongPtrW(a,0) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE) return 19;
	HWND fresh=CreateWindowExW(0,MAKEINTATOM(atom),L"fresh",WS_POPUP,0,0,32,24,NULL,NULL,instance,NULL);
	if (!fresh || created!=3 || GetWindowLongPtrW(fresh,0) || (ULONG_PTR)GetClassLongPtrW(fresh,0)!=0x1122331234567888ULL) return 20;
	if (!DestroyWindow(fresh) || !DestroyWindow(b) || !UnregisterClassW(MAKEINTATOM(atom),instance)) return 21;
	definition.cbClsExtra=41; definition.cbWndExtra=41;
	atom=RegisterClassExW(&definition);
	if (!atom || !UnregisterClassW(MAKEINTATOM(atom),instance)) return 22;
	phase=1;
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static HWND first,second;
static char events[256];
static unsigned count;
__declspec(dllexport) volatile unsigned phase;

static char tag(HWND window)
{
	return !window ? '0' : window==first ? '1' : window==second ? '2' : '3';
}

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	char event=message==WM_SETFOCUS ? 'A' : message==WM_KILLFOCUS ? 'B' :
		message==WM_ACTIVATE ? 'C' : message==WM_NCACTIVATE ? 'D' : message==WM_DESTROY ? 'E' : 0;
	if (event && count+4<=sizeof(events)) {
		events[count++]=event; events[count++]=tag(GetFocus()); events[count++]=tag(GetActiveWindow());
		events[count++]=tag(event=='A' || event=='B' ? (HWND)wparam : event=='E' ? window : (HWND)lparam);
	}
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition); definition.hInstance=instance;
	definition.lpfnWndProc=procedure; definition.lpszClassName=L"RavenFocusContract";
	ATOM atom=RegisterClassExW(&definition);
	if (!atom) return 1;
	first=CreateWindowExW(0,MAKEINTATOM(atom),L"first",WS_POPUP,12,23,32,32,NULL,NULL,instance,NULL);
	second=CreateWindowExW(0,MAKEINTATOM(atom),L"second",WS_POPUP,-10,-20,40,50,NULL,NULL,instance,NULL);
	if (!first || !second || GetFocus() || GetActiveWindow()) return 2;
	RECT rect;
	if (!GetClientRect(second,&rect) || rect.left || rect.top || rect.right!=40 || rect.bottom!=50) return 3;
	if (!GetWindowRect(second,&rect) || rect.left!=-10 || rect.top!=-20 || rect.right!=30 || rect.bottom!=30) return 4;
	if (SetFocus(first)!=first || GetFocus()!=first || GetActiveWindow()!=first) return 5;
	unsigned before=count;
	if (SetFocus(first)!=first || count!=before) return 6;
	if (SetFocus(second)!=second || GetFocus()!=second || GetActiveWindow()!=second) return 7;
	if (SetFocus(NULL)!=second || GetFocus() || GetActiveWindow()!=second) return 8;
	if (SetFocus(first)!=first || !DestroyWindow(first) || GetFocus() || GetActiveWindow()) return 9;
	if (!DestroyWindow(second)) return 10;
	static const char expected[]="D010C010A110D112C112D121C121B222A221B020D021C021D012C012A110D110C110B000E001E002";
	if (count!=sizeof(expected)-1) return 11;
	for (unsigned index=0;index<count;++index) if (events[index]!=expected[index]) return 12;
	SetLastError(0);
	if (SetFocus(first) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE || GetFocus() || GetActiveWindow()) return 13;
	SetLastError(0);
	if (GetClientRect(first,&rect) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE) return 14;
	if (!UnregisterClassW(MAKEINTATOM(atom),instance)) return 15;
	phase=1;
	return 0;
}

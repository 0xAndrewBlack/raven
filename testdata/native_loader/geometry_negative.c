#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static unsigned removed;
static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_NCCALCSIZE) { ((RECT *)lparam)->left=(-2147483647L-1); return 0; }
	if (message==WM_NCDESTROY) ++removed;
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition); definition.hInstance=instance;
	definition.lpfnWndProc=procedure; definition.lpszClassName=L"RavenGeometryBoundary";
	ATOM atom=RegisterClassExW(&definition);
	if (!atom) return 1;
	SetLastError(0);
	if (CreateWindowExW(0,MAKEINTATOM(atom),L"geometry",WS_POPUP,1,2,32,32,NULL,NULL,instance,NULL) ||
		GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED || removed!=1) return 2;
	if (!UnregisterClassW(MAKEINTATOM(atom),instance)) return 3;
	return 0;
}

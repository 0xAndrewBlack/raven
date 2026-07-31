#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

__declspec(dllexport) HINSTANCE class_instance;
static ATOM class_atom;

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_APP) return 91;
	return DefWindowProcW(window,message,wparam,lparam);
}

BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,void *reserved)
{
	(void)reserved;
	if (reason==DLL_PROCESS_ATTACH) {
		class_instance=instance;
		WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition);
		definition.style=CS_GLOBALCLASS; definition.hInstance=instance; definition.lpfnWndProc=procedure;
		definition.cbClsExtra=16; definition.cbWndExtra=24; definition.hbrBackground=GetStockObject(BLACK_BRUSH);
		definition.lpszClassName=L"RavenGlobalModule";
		class_atom=RegisterClassExW(&definition);
		return class_atom!=0;
	}
	if (reason==DLL_PROCESS_DETACH) return UnregisterClassW(MAKEINTATOM(class_atom),instance);
	return TRUE;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllexport) DWORD sequence,after_exit,phase;

#if RAVEN_EXIT_MODE==1
static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_USER) { ExitProcess(0x12345678); after_exit=1; }
	if (message==WM_DESTROY) after_exit=2;
	return DefWindowProcW(window,message,wparam,lparam);
}
#endif

int raven_entry(void)
{
	phase=1;
	HMODULE module=LoadLibraryW(
#if RAVEN_EXIT_MODE==2
		L"exit-attach.dll"
#elif RAVEN_EXIT_MODE==3
		L"exit-tls.dll"
#elif RAVEN_EXIT_MODE==4 || RAVEN_EXIT_MODE==5
		L"exit-repeat.dll"
#elif RAVEN_EXIT_MODE==8
		L"exit-fault.dll"
#else
		L"exit-basic.dll"
#endif
	);
	if (!module) return 91;
	phase=2;
	BOOL (*observe)(DWORD *,DWORD *,BOOL)=(BOOL (*)(DWORD *,DWORD *,BOOL))GetProcAddress(module,"ObserveExit");
	if (!observe || !observe(&sequence,&after_exit,RAVEN_EXIT_MODE!=5)) return 92;
#if RAVEN_EXIT_MODE==1
	HINSTANCE instance=GetModuleHandleW(NULL);
	WNDCLASSW definition={0}; definition.lpfnWndProc=procedure; definition.hInstance=instance; definition.lpszClassName=L"RavenExitCallback";
	if (!RegisterClassW(&definition)) return 93;
	HWND window=CreateWindowExW(0,definition.lpszClassName,L"Raven process exit",WS_POPUP,0,0,8,8,NULL,NULL,instance,NULL);
	if (!window) return 94;
	ShowWindow(window,SW_SHOW);
	HDC dc=GetDC(window); RECT rect={0,0,8,8};
	if (!dc || !FillRect(dc,&rect,GetStockObject(WHITE_BRUSH)) || ReleaseDC(window,dc)!=1) return 95;
	SendMessageW(window,WM_USER,0,0);
#elif RAVEN_EXIT_MODE==5
	FreeLibrary(module);
#elif RAVEN_EXIT_MODE==4
	ExitProcess(7);
#elif RAVEN_EXIT_MODE==6
	ExitProcess(0);
#elif RAVEN_EXIT_MODE==7
	ExitProcess(0x12345600);
#else
	ExitProcess(0x12345678);
#endif
	after_exit=3;
	return 96;
}

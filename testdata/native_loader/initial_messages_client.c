#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static unsigned mode,phase,failure,sizes,moves,destroyed,nonclient_destroyed;
__declspec(dllexport) volatile DWORD exit_phase;

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_CREATE) { phase=1; return mode==3 ? -1 : 0; }
	if (message==WM_SIZE) {
		++sizes;
		if (phase!=1 || wparam || LOWORD(lparam)!=320 || HIWORD(lparam)!=240) failure=1;
		phase=2;
#ifdef EXIT_DURING_SIZE
		if (failure) ExitProcess(0x1000+failure);
		exit_phase=2; ExitProcess(0x1234);
#endif
		if (mode==1 && !DestroyWindow(window)) failure=2;
		return 0;
	}
	if (message==WM_MOVE) {
		++moves;
		if (phase!=2 || wparam || (SHORT)LOWORD(lparam)!=-40 || HIWORD(lparam)!=50) failure=3;
		phase=3;
		if (mode==2 && !DestroyWindow(window)) failure=4;
		return 0;
	}
	if (message==WM_DESTROY) { ++destroyed; return 0; }
	if (message==WM_NCDESTROY) { ++nonclient_destroyed; return 0; }
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	WNDCLASSW definition={0};
	definition.lpfnWndProc=procedure;
	definition.hInstance=GetModuleHandleW(NULL);
	definition.lpszClassName=L"raven.initial.messages";
	if (!RegisterClassW(&definition)) return 1;
	for (mode=0;mode<4;++mode) {
		phase=failure=sizes=moves=destroyed=nonclient_destroyed=0;
		HWND window=CreateWindowExW(0,definition.lpszClassName,L"initial messages",WS_POPUP,-40,50,320,240,NULL,NULL,definition.hInstance,NULL);
		if (failure) return 2;
		if (!mode) {
			if (!window || !IsWindow(window) || phase!=3 || sizes!=1 || moves!=1 || destroyed || nonclient_destroyed) return 3;
			if (!DestroyWindow(window)) return 4;
		} else {
			if (window || IsWindow(window) || nonclient_destroyed!=1) return 5;
			if (mode==1 && (sizes!=1 || moves || destroyed!=1)) return 6;
			if (mode==2 && (sizes!=1 || moves!=1 || destroyed!=1)) return 7;
			if (mode==3 && (sizes || moves || destroyed)) return 8;
		}
	}
	if (!UnregisterClassW(definition.lpszClassName,definition.hInstance)) return 9;
	return 0;
}

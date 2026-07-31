#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static LRESULT CALLBACK procedure(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	return DefWindowProcW(window,message,wparam,lparam);
}

int raven_entry(void)
{
	WNDCLASSW definition={0};
	definition.lpfnWndProc=procedure;
	definition.hInstance=GetModuleHandleW(NULL);
	definition.lpszClassName=L"raven.coordinate.client";
	if (!RegisterClassW(&definition)) return 1;
	HWND a=CreateWindowExW(0,definition.lpszClassName,L"a",WS_POPUP,20,30,320,240,NULL,NULL,definition.hInstance,NULL);
	HWND b=CreateWindowExW(0,definition.lpszClassName,L"b",WS_POPUP,-40,50,320,240,NULL,NULL,definition.hInstance,NULL);
	if (!a || !b) return 2;
	HWND from[]={a,b,NULL,a,NULL,(HWND)0x12345,a,(HWND)0x12345};
	HWND to[]={b,a,a,a,NULL,a,(HWND)0x12345,a};
	const UINT counts[]={3,3,3,0,0,3,3,0};
	const int dx[]={60,-60,-20,0,0,0,0,0},dy[]={-20,20,-30,0,0,0,0,0};
	for (unsigned j=0;j<8;++j) {
		POINT points[]={{0,0},{-5,9},{100,-200}};
		const POINT original[]={{0,0},{-5,9},{100,-200}};
		SetLastError(0x7654);
		const UINT result=(UINT)MapWindowPoints(from[j],to[j],points,counts[j]);
		if (result != ((UINT)(WORD)dx[j] | ((UINT)(WORD)dy[j]<<16))) return 3;
		if (GetLastError() != (j>=5 ? ERROR_INVALID_WINDOW_HANDLE : 0x7654)) return 4;
		for (unsigned i=0;i<3;++i)
			if (points[i].x != original[i].x+dx[j] || points[i].y != original[i].y+dy[j]) return 5;
	}
	POINT point={-5,9};
	SetLastError(0x7654);
	if (!ScreenToClient(a,&point) || point.x!=-25 || point.y!=-21 || GetLastError()!=0x7654) return 6;
	if (!ClientToScreen(a,&point) || point.x!=-5 || point.y!=9 || GetLastError()!=0x7654) return 7;
	if ((UINT)MapWindowPoints(a,b,NULL,0)!=(60U | ((UINT)(WORD)-20<<16)) || GetLastError()!=0x7654) return 11;
	point.x=0; point.y=0;
	if (ClientToScreen(NULL,&point) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE || point.x || point.y) return 12;
	if (ScreenToClient(NULL,&point) || GetLastError()!=ERROR_INVALID_WINDOW_HANDLE || point.x || point.y) return 13;
	point.x=0x7fffffff; point.y=(LONG)0x80000000U;
	SetLastError(0x7654);
	if (!ClientToScreen(a,&point) || point.x!=(LONG)0x80000013U || point.y!=(LONG)0x8000001eU || GetLastError()!=0x7654) return 14;
	RECT client,outer;
	if (!GetClientRect(a,&client) || !GetWindowRect(a,&outer)) return 8;
	if (client.left || client.top || client.right!=320 || client.bottom!=240 ||
		outer.left!=20 || outer.top!=30 || outer.right!=340 || outer.bottom!=270) return 9;
	if (!DestroyWindow(a) || !DestroyWindow(b) || !UnregisterClassW(definition.lpszClassName,definition.hInstance)) return 10;
	return 0;
}

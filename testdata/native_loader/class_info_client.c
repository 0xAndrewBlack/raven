#define WIN32_LEAN_AND_MEAN
#define UNICODE
#include <windows.h>

static LRESULT CALLBACK one(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_APP) return 1;
	return DefWindowProcW(window,message,wparam,lparam);
}

static LRESULT CALLBACK two(HWND window,UINT message,WPARAM wparam,LPARAM lparam)
{
	if (message==WM_APP) return 2;
	return DefWindowProcW(window,message,wparam,lparam);
}

static void fill(void *buffer,unsigned size)
{
	unsigned char *bytes=buffer;
	for (unsigned i=0;i<size;++i) bytes[i]=0x77;
}

int raven_entry(void)
{
	HINSTANCE instance=GetModuleHandleW(NULL),other=(HINSTANCE)0x12340000,global_instance=(HINSTANCE)0x56780000,foreign=(HINSTANCE)0x77770000;
	WNDCLASSEXW definition={0}; definition.cbSize=sizeof(definition); definition.hInstance=instance;
	definition.lpfnWndProc=one; definition.lpszClassName=L"MiXeDIdentity"; definition.cbClsExtra=16; definition.cbWndExtra=24;
	ATOM local=RegisterClassExW(&definition);
	definition.hInstance=other; definition.lpfnWndProc=two; definition.lpszClassName=L"mIXEDiDENTITY";
	ATOM second=RegisterClassExW(&definition);
	if (!local || second!=local) return 1;
	const WCHAR *query=L"mixedidentity";
	WNDCLASSEXW out; fill(&out,sizeof(out)); out.cbSize=77;
	SetLastError(0x5555);
	if (GetClassInfoExW(instance,query,&out)!=local || GetLastError()!=0x5555 || out.cbSize!=77 || out.lpfnWndProc!=one ||
		out.hInstance!=instance || out.cbClsExtra!=16 || out.cbWndExtra!=24 || out.lpszClassName!=query) return 2;
	fill(&out,sizeof(out)); out.cbSize=0;
	if (GetClassInfoExW(other,MAKEINTATOM(local),&out)!=local || out.cbSize || out.lpfnWndProc!=two || out.lpszClassName!=MAKEINTATOM(local)) return 3;
	fill(&out,sizeof(out));
	if (GetClassInfoExW(foreign,L"mixedidentity",&out) || GetLastError()!=ERROR_CLASS_DOES_NOT_EXIST || out.style!=0x77777777) return 4;
	definition.hInstance=global_instance; definition.lpfnWndProc=one; definition.style=CS_GLOBALCLASS;
	ATOM global=RegisterClassExW(&definition);
	if (global!=local) return 5;
	definition.hInstance=foreign;
	if (RegisterClassExW(&definition) || GetLastError()!=ERROR_CLASS_ALREADY_EXISTS) return 6;
	if (GetClassInfoExW(foreign,MAKEINTATOM(global),&out)!=global || out.style!=CS_GLOBALCLASS || out.hInstance!=foreign || out.lpfnWndProc!=one) return 7;
	if (GetClassInfoExW(instance,MAKEINTATOM(global),&out)!=local || out.style || out.lpfnWndProc!=one ||
		GetClassInfoExW(other,L"mixedidentity",&out)!=second || out.style || out.lpfnWndProc!=two) return 8;
	if (GetClassInfoExW(NULL,MAKEINTATOM(global),&out)!=global || out.hInstance || out.lpfnWndProc!=one) return 9;
	WNDCLASSW plain; fill(&plain,sizeof(plain));
	if (GetClassInfoW(other,MAKEINTATOM(local),&plain)!=local || plain.lpfnWndProc!=two || plain.hInstance!=other ||
		plain.lpszClassName!=MAKEINTATOM(local) || plain.cbClsExtra!=16 || plain.cbWndExtra!=24) return 10;
	HWND a=CreateWindowExW(0,MAKEINTATOM(local),L"a",WS_POPUP,0,0,16,16,NULL,NULL,instance,NULL);
	HWND b=CreateWindowExW(0,L"mixedidentity",L"b",WS_POPUP,0,0,16,16,NULL,NULL,other,NULL);
	HWND c=CreateWindowExW(0,MAKEINTATOM(global),L"c",WS_POPUP,0,0,16,16,NULL,NULL,foreign,NULL);
	if (!a || !b || !c || SendMessageW(a,WM_APP,0,0)!=1 || SendMessageW(b,WM_APP,0,0)!=2 || SendMessageW(c,WM_APP,0,0)!=1 ||
		GetClassLongPtrW(b,GCW_ATOM)!=local || GetClassLongPtrW(c,GCLP_HMODULE)!=(ULONG_PTR)global_instance) return 11;
	if (SetClassLongPtrW(a,0,0x1234) || GetClassLongPtrW(b,0) || GetClassLongPtrW(c,0) || GetClassLongPtrW(a,0)!=0x1234) return 12;
	WCHAR wide[256]; char narrow[256]; fill(wide,sizeof(wide)); fill(narrow,sizeof(narrow));
	if (GetClassNameW(a,wide,256)!=13 || wide[0]!='M' || wide[1]!='i' || wide[2]!='X' || wide[13] ||
		GetClassNameW(b,wide,256)!=13 || wide[0]!='m' || wide[1]!='I' || wide[2]!='X' ||
		GetClassNameA(b,narrow,256)!=13 || narrow[0]!='m' || narrow[1]!='I' || narrow[13]) return 13;
	wide[0]=wide[1]=wide[2]=0x7777; SetLastError(0x5555);
	if (GetClassNameW(a,wide,2)!=1 || wide[0]!='M' || wide[1] || wide[2]!=0x7777 || GetLastError()!=0x5555) return 14;
	wide[0]=0x7777;
	if (GetClassNameW(a,wide,1) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || wide[0]!=0x7777 ||
		GetClassNameW(a,wide,0) || GetLastError()!=ERROR_INSUFFICIENT_BUFFER || wide[0]!=0x7777 || GetClassNameW(a,wide,-1)!=13) return 15;
#ifdef RAVEN_CLASS_INFO_BOUNDARY
	WNDCLASSEXW unsupported=definition; unsupported.style=CS_GLOBALCLASS | CS_DBLCLKS; unsupported.lpszClassName=L"UnsupportedClassStyle";
	if (RegisterClassExW(&unsupported) || GetLastError()!=ERROR_CALL_NOT_IMPLEMENTED) return 40;
#endif
	if (!DestroyWindow(c) || !UnregisterClassW(MAKEINTATOM(global),foreign) || !IsWindow(a) || !IsWindow(b)) return 16;
	if (!DestroyWindow(a) || !UnregisterClassW(MAKEINTATOM(local),instance) || !IsWindow(b) || SendMessageW(b,WM_APP,0,0)!=2) return 17;
	if (GetClassInfoExW(instance,MAKEINTATOM(local),&out) || GetLastError()!=ERROR_CLASS_DOES_NOT_EXIST ||
		!DestroyWindow(b) || !UnregisterClassW(MAKEINTATOM(second),other)) return 18;
	definition.hInstance=instance; definition.style=CS_GLOBALCLASS; definition.lpszClassName=L"SameModuleScopes";
	global=RegisterClassExW(&definition); definition.style=0; definition.lpfnWndProc=two; local=RegisterClassExW(&definition);
	if (!global || local!=global || GetClassInfoExW(instance,MAKEINTATOM(global),&out)!=local || out.lpfnWndProc!=two || out.style ||
		!UnregisterClassW(MAKEINTATOM(local),instance) || GetClassInfoExW(instance,MAKEINTATOM(global),&out)!=global || out.style!=CS_GLOBALCLASS ||
		!UnregisterClassW(MAKEINTATOM(global),instance)) return 19;
	HMODULE module=LoadLibraryW(L"class-module.dll");
	HINSTANCE *owner=module ? (HINSTANCE *)GetProcAddress(module,"class_instance") : NULL;
	if (!module || !owner || *owner!=module || !GetClassInfoExW(instance,L"RavenGlobalModule",&out) || out.style!=CS_GLOBALCLASS ||
		out.hInstance!=instance || out.cbClsExtra!=16 || out.cbWndExtra!=24 || out.hbrBackground!=GetStockObject(BLACK_BRUSH)) return 20;
	HWND control=CreateWindowExW(0,L"RavenGlobalModule",L"module",WS_POPUP,0,0,16,16,NULL,NULL,instance,NULL);
	if (!control || GetClassLongPtrW(control,GCLP_HMODULE)!=(ULONG_PTR)module || SendMessageW(control,WM_APP,0,0)!=91 ||
		!DestroyWindow(control) || !FreeLibrary(module)) return 21;
	fill(&out,sizeof(out));
	if (GetClassInfoExW(instance,L"RavenGlobalModule",&out) || GetLastError()!=ERROR_CLASS_DOES_NOT_EXIST || out.style!=0x77777777) return 22;
	return 0;
}

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

__declspec(dllexport) STARTUPINFOA startup_a_before,startup_a_after;
__declspec(dllexport) STARTUPINFOW startup_w_before,startup_w_after;
__declspec(dllexport) ULONGLONG startup_title_digest;

static void poison(void *pointer,BYTE value)
{
	for(unsigned i=0;i<104;++i)((BYTE *)pointer)[i]=value;
}
int raven_entry(void)
{
	PEB *peb;__asm__("movq %%gs:0x60,%0":"=r"(peb));
	BYTE *parameters=(BYTE *)peb->ProcessParameters;
	DWORD *x=(DWORD *)(parameters+0x88),*flags=(DWORD *)(parameters+0xa4),*show=(DWORD *)(parameters+0xa8);
	DWORD original_x=*x,original_flags=*flags,original_show=*show;
	WCHAR **title=(WCHAR **)(parameters+0xb8),**desktop=(WCHAR **)(parameters+0xc8);
	WCHAR *original_title=*title,*original_desktop=*desktop;
	WORD runtime_size=*(WORD *)(parameters+0xe0);
	BYTE *runtime=*(BYTE **)(parameters+0xe8);
	WCHAR changed_title[]=L"changed",changed_desktop[]=L"desktop";
	*x=111;*flags=0x101;*show=0x12345678;*title=changed_title;*desktop=changed_desktop;
	poison(&startup_a_before,0xa5);poison(&startup_w_before,0x5a);
	SetLastError(0x7654);GetStartupInfoA(&startup_a_before);GetStartupInfoW(&startup_w_before);
	BOOL correct=startup_a_before.cb==104 && startup_w_before.cb==104 && startup_a_before.dwX==original_x &&
		startup_a_before.dwFlags==original_flags && startup_a_before.wShowWindow==(WORD)original_show &&
		startup_w_before.dwX==111 && startup_w_before.dwFlags==0x101 && startup_w_before.wShowWindow==0x5678 &&
		startup_w_before.lpTitle==changed_title && startup_w_before.lpDesktop==changed_desktop &&
		!startup_a_before.lpReserved && !startup_w_before.lpReserved &&
		startup_a_before.cbReserved2==runtime_size && startup_w_before.cbReserved2==runtime_size &&
		startup_a_before.lpReserved2==runtime && startup_w_before.lpReserved2==runtime && GetLastError()==0x7654;
	startup_title_digest=14695981039346656037ULL;
	if(runtime_size==5) {
		const BYTE expected[]={0xaa,0,0xbb,0xcc,0xdd};
		for(unsigned i=0;i<5;++i) if(!runtime || runtime[i]!=expected[i]) correct=FALSE;
	}
	if(!startup_a_before.lpTitle) correct=FALSE;
	else for(const BYTE *byte=(BYTE *)startup_a_before.lpTitle;*byte;++byte)
		startup_title_digest=(startup_title_digest^*byte)*1099511628211ULL;
	*flags=0;*x=222;*show=9;
	poison(&startup_a_after,0xa5);poison(&startup_w_after,0x5a);
	GetStartupInfoA(&startup_a_after);GetStartupInfoW(&startup_w_after);
	for(unsigned i=0;i<104;++i) if(((BYTE *)&startup_a_before)[i]!=((BYTE *)&startup_a_after)[i]) correct=FALSE;
	for(unsigned i=0;i<4;++i)
		if(((BYTE *)&startup_w_after)[4+i]!=0x5a || ((BYTE *)&startup_w_after)[68+i]!=0x5a ||
			((BYTE *)&startup_a_after)[4+i] || ((BYTE *)&startup_a_after)[68+i]) correct=FALSE;
	for(unsigned i=80;i<104;++i) if(((BYTE *)&startup_w_after)[i]!=0x5a) correct=FALSE;
	if(startup_w_after.dwFlags || startup_w_after.dwX!=222 || startup_w_after.wShowWindow!=9 || GetLastError()!=0x7654) correct=FALSE;
	*x=original_x;*flags=original_flags;*show=original_show;*title=original_title;*desktop=original_desktop;
	return correct ? 0 : 1;
}

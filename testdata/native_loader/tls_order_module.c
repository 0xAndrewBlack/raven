#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static DWORD state,index;
static DWORD *observed;
static BOOL terminating;
static BYTE template[1]={7};

static void record(DWORD event)
{
	state=state*10+event;
	if (observed) *observed=state;
}

static void NTAPI tls_callback(PVOID module,DWORD reason,PVOID reserved)
{
	(void)module;
	if (reason==DLL_PROCESS_ATTACH) {
		if (reserved) RaiseException(0xe0000051,1,0,NULL);
		record(1);
	} else if (reason==DLL_PROCESS_DETACH) {
		if (reserved || state!=12) RaiseException(0xe0000052,1,0,NULL);
		record(3);
	}
}

static PIMAGE_TLS_CALLBACK callbacks[]={tls_callback,NULL};
const IMAGE_TLS_DIRECTORY64 _tls_used __attribute__((section(".rdata$T")))={
	(ULONGLONG)template,(ULONGLONG)(template+1),(ULONGLONG)&index,(ULONGLONG)callbacks,0,0};

__declspec(dllexport) BOOL ObserveDetach(DWORD *output,BOOL shutdown)
{
	if (!output || state!=12) return FALSE;
	observed=output; terminating=shutdown; *observed=state;
	return TRUE;
}

BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved)
{
	(void)module;
	if (reason==DLL_PROCESS_ATTACH) {
		if (reserved || state!=1) return FALSE;
		record(2);
	} else if (reason==DLL_PROCESS_DETACH) {
		if (state!=123 || !!reserved!=!!terminating) RaiseException(0xe0000050,1,0,NULL);
		record(4);
	}
	return TRUE;
}

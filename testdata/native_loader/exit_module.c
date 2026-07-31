#define WIN32_LEAN_AND_MEAN
#include <windows.h>

__declspec(dllexport) DWORD exit_trace;
static DWORD index;
static BYTE template[1]={7};
static DWORD *observed,*guard;
static BOOL terminating;

static void record(DWORD event)
{
	exit_trace=exit_trace*10+event;
	if (observed) *observed=exit_trace;
}

static void NTAPI callback(PVOID module,DWORD reason,PVOID reserved)
{
	(void)module;
	if (reason==DLL_PROCESS_ATTACH) {
		if (reserved) RaiseException(0xe0000061,1,0,NULL);
		record(1);
#ifdef RAVEN_EXIT_TLS
		ExitProcess(0x12345678);
#endif
	} else if (reason==DLL_PROCESS_DETACH) {
		if (reserved || exit_trace!=12) RaiseException(0xe0000062,1,0,NULL);
		record(3);
	}
}
static PIMAGE_TLS_CALLBACK callbacks[]={callback,NULL};
const IMAGE_TLS_DIRECTORY64 _tls_used __attribute__((section(".rdata$T")))={
	(ULONGLONG)template,(ULONGLONG)(template+1),(ULONGLONG)&index,(ULONGLONG)callbacks,0,0};

__declspec(dllexport) BOOL ObserveExit(DWORD *output,DWORD *after,BOOL shutdown)
{
	if (!output || !after || exit_trace!=12) return FALSE;
	observed=output; guard=after; terminating=shutdown; *observed=exit_trace;
	return TRUE;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved)
{
	(void)module;
	if (reason==DLL_PROCESS_ATTACH) {
		if (reserved || exit_trace!=1) return FALSE;
		record(2);
#ifdef RAVEN_EXIT_ATTACH
		ExitProcess(0x12345678);
#endif
	} else if (reason==DLL_PROCESS_DETACH) {
		if (exit_trace!=123 || !!reserved!=!!terminating || (guard && *guard)) RaiseException(0xe0000063,1,0,NULL);
		record(4);
#ifdef RAVEN_EXIT_REPEAT
		ExitProcess(9);
#endif
#ifdef RAVEN_EXIT_FAULT
		RaiseException(0xe0000066,1,0,NULL);
#endif
	}
	return TRUE;
}

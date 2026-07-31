#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

static DWORD phase,index;
static BYTE template[1];

static BOOL parameters_valid(void)
{
	PEB *peb;
	__asm__("movq %%gs:0x60,%0":"=r"(peb));
	RTL_USER_PROCESS_PARAMETERS *parameters=peb->ProcessParameters;
	if (!parameters || !parameters->ImagePathName.Buffer || !parameters->ImagePathName.Length ||
		!parameters->CommandLine.Buffer || parameters->ImagePathName.Length%2 || parameters->CommandLine.Length%2 ||
		parameters->ImagePathName.MaximumLength<parameters->ImagePathName.Length+2 ||
		parameters->CommandLine.MaximumLength<parameters->CommandLine.Length+2 ||
		parameters->ImagePathName.Buffer[parameters->ImagePathName.Length/2] ||
		parameters->CommandLine.Buffer[parameters->CommandLine.Length/2]) return FALSE;
	SetLastError(0x7654);
	WCHAR *command=GetCommandLineW();
	CHAR *ansi=GetCommandLineA();
	if (!ansi || ansi!=GetCommandLineA() || GetACP()!=1252 || command!=parameters->CommandLine.Buffer || command!=GetCommandLineW()) return FALSE;
	if (*command) {
		WCHAR saved=*command; CHAR original=*ansi;
		*command=L'!'; BOOL cached=ansi==GetCommandLineA() && *ansi==original; *command=saved;
		if (!cached) return FALSE;
	}
	STARTUPINFOA startup_a;STARTUPINFOW startup_w;
	for (unsigned i=0;i<sizeof(startup_a);++i) ((BYTE *)&startup_a)[i]=0xa5;
	for (unsigned i=0;i<sizeof(startup_w);++i) ((BYTE *)&startup_w)[i]=0x5a;
	GetStartupInfoA(&startup_a);GetStartupInfoW(&startup_w);
	if (startup_a.cb!=sizeof(startup_a) || startup_w.cb!=sizeof(startup_w) ||
		startup_a.wShowWindow!=1 || startup_w.wShowWindow!=1 || ((BYTE *)&startup_a)[4] || ((BYTE *)&startup_w)[4]!=0x5a)
		return FALSE;
	return GetLastError()==0x7654;
}

static void NTAPI callback(PVOID module,DWORD reason,PVOID reserved)
{
	(void)module; (void)reserved;
	if (reason==DLL_PROCESS_ATTACH) {
		if (!parameters_valid()) RaiseException(0xe0000070,1,0,NULL);
		phase=1;
	}
}
static PIMAGE_TLS_CALLBACK callbacks[]={callback,NULL};
const IMAGE_TLS_DIRECTORY64 _tls_used __attribute__((section(".rdata$T")))={
	(ULONGLONG)template,(ULONGLONG)(template+1),(ULONGLONG)&index,(ULONGLONG)callbacks,0,0};

#ifdef RAVEN_PARAMETER_DLL
__declspec(dllexport) DWORD ParameterPhase(void) { return phase; }
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved)
{
	(void)module; (void)reserved;
	if (reason==DLL_PROCESS_ATTACH) {
		if (phase!=1 || !parameters_valid()) return FALSE;
		phase=12;
	}
	return TRUE;
}
#else
__declspec(dllimport) DWORD ParameterPhase(void);
__declspec(dllexport) ULONGLONG command_digest;
__declspec(dllexport) ULONGLONG ansi_digest;
int raven_entry(void)
{
	if (phase!=1 || ParameterPhase()!=12 || !parameters_valid()) return 1;
	command_digest=14695981039346656037ULL;
	for (const WCHAR *character=GetCommandLineW();*character;++character)
		command_digest=(command_digest^*character)*1099511628211ULL;
	ansi_digest=14695981039346656037ULL;
	for (const BYTE *character=(const BYTE *)GetCommandLineA();*character;++character)
		ansi_digest=(ansi_digest^*character)*1099511628211ULL;
	return 0;
}
#endif

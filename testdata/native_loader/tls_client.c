#include <windows.h>
#include <stdint.h>

#ifndef RAVEN_TLS_ALIGNMENT
#define RAVEN_TLS_ALIGNMENT 16
#define RAVEN_TLS_ALIGN_FLAG IMAGE_SCN_ALIGN_16BYTES
#endif

struct tls_block {
	uint32_t value;
	uint32_t marker;
	uint64_t zero;
};

__declspec(dllexport) DWORD _tls_index;
__declspec(dllexport) volatile DWORD tls_state;
static struct tls_block template = {17, 0x12345678, 0};

static struct tls_block *current_tls(void)
{
	uintptr_t *slots;
#ifdef _WIN64
	__asm__("movq %%gs:0x58,%0" : "=r"(slots));
#else
	__asm__("movl %%fs:0x2c,%0" : "=r"(slots));
#endif
#ifdef RAVEN_TLS_DLL
	return (struct tls_block *)slots[_tls_index];
#else
	/* Executable TLS access can use slot zero directly, as MSVC does. */
	return (struct tls_block *)slots[0];
#endif
}

static void NTAPI first_callback(PVOID module, DWORD reason, PVOID reserved)
{
	(void)module;
	struct tls_block *block = current_tls();
	if (reason == DLL_PROCESS_ATTACH) {
		if (reserved || block->value != 17 || block->marker != 0x12345678 || block->zero || ((uintptr_t)block & (RAVEN_TLS_ALIGNMENT - 1))) {
			tls_state = 900;
			return;
		}
		block->value = 19;
		block->zero = 77;
		tls_state = 1;
		SetLastError(71);
	} else if (reason == DLL_PROCESS_DETACH) {
		tls_state = tls_state * 10 + 5;
	}
}

static void NTAPI second_callback(PVOID module, DWORD reason, PVOID reserved)
{
	(void)module;
	(void)reserved;
	if (reason == DLL_PROCESS_ATTACH) {
		if (tls_state != 1 || current_tls()->value != 19 || current_tls()->zero != 77 || GetLastError() != 71) {
			tls_state = 901;
			return;
		}
		tls_state = 12;
	} else if (reason == DLL_PROCESS_DETACH) {
		tls_state = tls_state * 10 + 6;
	}
}

static PIMAGE_TLS_CALLBACK callbacks[] = {first_callback, second_callback, 0};
#ifdef _WIN64
const IMAGE_TLS_DIRECTORY64 _tls_used __attribute__((section(".rdata$T"))) = {
	(ULONGLONG)&template, (ULONGLONG)&template + 8,
	(ULONGLONG)&_tls_index, (ULONGLONG)callbacks, 8, RAVEN_TLS_ALIGN_FLAG
};
#else
const IMAGE_TLS_DIRECTORY32 _tls_used __attribute__((section(".rdata$T"))) = {
	(DWORD)&template, (DWORD)&template + 8,
	(DWORD)&_tls_index, (DWORD)callbacks, 8, RAVEN_TLS_ALIGN_FLAG
};
#endif

#ifdef RAVEN_TLS_DLL
__declspec(dllexport) DWORD ReadTLSValue(void)
{
	return current_tls()->value;
}

__declspec(dllexport) DWORD WriteTLSValue(DWORD value)
{
	const DWORD previous = current_tls()->value;
	current_tls()->value = value;
	return previous;
}

__declspec(dllexport) DWORD QueryTLS(void)
{
	return tls_state == 123 && current_tls()->value == 19 && current_tls()->zero == 77;
}

BOOL WINAPI DllMain(HINSTANCE module, DWORD reason, LPVOID reserved)
{
	(void)module;
	if (reason == DLL_PROCESS_ATTACH) {
#ifdef RAVEN_TLS_DYNAMIC
		if (reserved || tls_state != 12)
#elif defined(_WIN64)
		if (!reserved || tls_state != 12)
#else
		if (tls_state != 12)
#endif
			return FALSE;
		tls_state = 123;
	} else if (reason == DLL_PROCESS_DETACH) {
		tls_state = tls_state * 10 + 4;
	}
	return TRUE;
}
#else
__declspec(dllimport) DWORD QueryTLS(void);
__declspec(dllimport) DWORD ReadTLSValue(void);
__declspec(dllexport) volatile DWORD entered;

static DWORD WINAPI worker(void *argument)
{
	(void)argument;
	struct tls_block *block = current_tls();
	if (_tls_index || block->value != 17 || block->marker != 0x12345678 || block->zero || ReadTLSValue() != 17)
		return 1;
	block->value = 37;
	return ReadTLSValue() != 17;
}

DWORD raven_entry(void)
{
	entered = 1;
	if (_tls_index)
		return 12;
	if (tls_state != 12 || !QueryTLS() || current_tls()->value != 19 || current_tls()->zero != 77)
		return 10;
	current_tls()->value = 25;
	if (!QueryTLS())
		return 11;
	HANDLE thread = CreateThread(NULL, 0, worker, NULL, 0, NULL);
	DWORD result = 99;
	if (!thread || WaitForSingleObject(thread, 5000) != WAIT_OBJECT_0 || !GetExitCodeThread(thread, &result) || result ||
		current_tls()->value != 25 || !QueryTLS())
		return 13;
	CloseHandle(thread);
	tls_state = 123;
	return 0;
}
#endif

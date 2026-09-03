#include <rtl.h>

/* The kernel32 functions a program calls most often, run in the guest as Windows runs them in user mode: the process heap, critical
 * sections, SRW locks and the waking of condition variables. The runtime forwards kernel32's exports of these names here, so a call
 * costs what a function call costs. Waiting stays with the runtime's scheduler: a lock that is held, and a condition variable with
 * sleepers, go to the runtime's implementation through ntdll. */

#define LAST_ERROR (*(volatile ULONG *)((PUCHAR)NtCurrentTeb() + 0x68))
#define THREAD_ID ((ULONG)(ULONG_PTR)NtCurrentTeb()->ClientId.UniqueThread)

/* The runtime's waits, served by its scheduler. */
VOID NTAPI RtlAcquireSRWLockExclusive(PRTL_SRWLOCK lock);
VOID NTAPI RtlAcquireSRWLockShared(PRTL_SRWLOCK lock);
VOID NTAPI RtlWakeConditionVariable(PRTL_CONDITION_VARIABLE variable);
VOID NTAPI RtlWakeAllConditionVariable(PRTL_CONDITION_VARIABLE variable);

/* ---- the heap: the flags kernel32 accepts, and the error it reports when the heap fails ---- */
PVOID WINAPI RavenHeapAlloc(HANDLE heap, ULONG flags, SIZE_T size)
{
	PVOID block;
	if (flags & ~13U) {
		LAST_ERROR = ERROR_CALL_NOT_IMPLEMENTED;
		return NULL;
	}
	block = RtlAllocateHeap(heap, flags, size);
	if (!block)
		LAST_ERROR = ERROR_NOT_ENOUGH_MEMORY;
	return block;
}

PVOID WINAPI RavenHeapReAlloc(HANDLE heap, ULONG flags, PVOID block, SIZE_T size)
{
	PVOID moved;
	if (flags & ~29U) {
		LAST_ERROR = ERROR_CALL_NOT_IMPLEMENTED;
		return NULL;
	}
	moved = RtlReAllocateHeap(heap, flags, block, size);
	if (!moved)
		LAST_ERROR = ERROR_NOT_ENOUGH_MEMORY;
	return moved;
}

BOOL WINAPI RavenHeapFree(HANDLE heap, ULONG flags, PVOID block)
{
	if (flags & ~1U) {
		LAST_ERROR = ERROR_CALL_NOT_IMPLEMENTED;
		return FALSE;
	}
	if (!RtlFreeHeap(heap, flags, block)) {
		LAST_ERROR = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	return TRUE;
}

SIZE_T WINAPI RavenHeapSize(HANDLE heap, ULONG flags, LPCVOID block)
{
	SIZE_T size;
	if (flags & ~1U) {
		LAST_ERROR = ERROR_CALL_NOT_IMPLEMENTED;
		return (SIZE_T)-1;
	}
	size = RtlSizeHeap(heap, flags, (PVOID)block);
	if (size == (SIZE_T)-1)
		LAST_ERROR = ERROR_INVALID_PARAMETER;
	return size;
}

HANDLE WINAPI RavenGetProcessHeap(VOID)
{
	return NtCurrentPeb()->ProcessHeap;
}

/* ---- critical sections: the RTL's own, without spinning, since only one guest thread runs at a time and spinning only delays the
   owner ---- */
VOID WINAPI RavenInitializeCriticalSection(PRTL_CRITICAL_SECTION section)
{
	RtlInitializeCriticalSectionAndSpinCount(section, 0);
}

BOOL WINAPI RavenInitializeCriticalSectionAndSpinCount(PRTL_CRITICAL_SECTION section, ULONG spin)
{
	return NT_SUCCESS(RtlInitializeCriticalSectionAndSpinCount(section, 0));
}

BOOL WINAPI RavenInitializeCriticalSectionEx(PRTL_CRITICAL_SECTION section, ULONG spin, ULONG flags)
{
	if (flags & ~0x03000000U) {
		LAST_ERROR = ERROR_INVALID_PARAMETER;
		return FALSE;
	}
	return NT_SUCCESS(RtlInitializeCriticalSectionAndSpinCount(section, 0));
}

VOID WINAPI RavenDeleteCriticalSection(PRTL_CRITICAL_SECTION section) { RtlDeleteCriticalSection(section); }
VOID WINAPI RavenEnterCriticalSection(PRTL_CRITICAL_SECTION section) { RtlEnterCriticalSection(section); }
VOID WINAPI RavenLeaveCriticalSection(PRTL_CRITICAL_SECTION section) { RtlLeaveCriticalSection(section); }
BOOL WINAPI RavenTryEnterCriticalSection(PRTL_CRITICAL_SECTION section) { return RtlTryEnterCriticalSection(section) ? TRUE : FALSE; }

/* ---- SRW locks: one word, 1 when held exclusively, shared holders counting in steps of 2, as the runtime keeps them; a lock that is
   busy is waited for by the runtime, which sees it become free when the scheduler looks again ---- */
VOID WINAPI RavenInitializeSRWLock(PRTL_SRWLOCK lock) { lock->Ptr = NULL; }

VOID WINAPI RavenAcquireSRWLockExclusive(PRTL_SRWLOCK lock)
{
	if (!InterlockedCompareExchangePointer(&lock->Ptr, (PVOID)1, NULL))
		return;
	RtlAcquireSRWLockExclusive(lock);
}

BOOLEAN WINAPI RavenTryAcquireSRWLockExclusive(PRTL_SRWLOCK lock)
{
	return InterlockedCompareExchangePointer(&lock->Ptr, (PVOID)1, NULL) == NULL;
}

VOID WINAPI RavenReleaseSRWLockExclusive(PRTL_SRWLOCK lock)
{
	InterlockedExchangePointer(&lock->Ptr, NULL);
}

VOID WINAPI RavenAcquireSRWLockShared(PRTL_SRWLOCK lock)
{
	ULONG_PTR value = (ULONG_PTR)lock->Ptr;
	if (!(value & 1) && InterlockedCompareExchangePointer(&lock->Ptr, (PVOID)(value + 2), (PVOID)value) == (PVOID)value)
		return;
	RtlAcquireSRWLockShared(lock);
}

BOOLEAN WINAPI RavenTryAcquireSRWLockShared(PRTL_SRWLOCK lock)
{
	for (;;) {
		ULONG_PTR value = (ULONG_PTR)lock->Ptr;
		if (value & 1)
			return FALSE;
		if (InterlockedCompareExchangePointer(&lock->Ptr, (PVOID)(value + 2), (PVOID)value) == (PVOID)value)
			return TRUE;
	}
}

VOID WINAPI RavenReleaseSRWLockShared(PRTL_SRWLOCK lock)
{
	for (;;) {
		ULONG_PTR value = (ULONG_PTR)lock->Ptr;
		if (value < 2)
			return;
		if (InterlockedCompareExchangePointer(&lock->Ptr, (PVOID)(value - 2), (PVOID)value) == (PVOID)value)
			return;
	}
}

/* ---- condition variables: the runtime keeps the number of sleepers in the variable, so waking one that nobody waits on is free ---- */
VOID WINAPI RavenInitializeConditionVariable(PRTL_CONDITION_VARIABLE variable) { variable->Ptr = NULL; }

VOID WINAPI RavenWakeConditionVariable(PRTL_CONDITION_VARIABLE variable)
{
	if (*(volatile PVOID *)&variable->Ptr)
		RtlWakeConditionVariable(variable);
}

VOID WINAPI RavenWakeAllConditionVariable(PRTL_CONDITION_VARIABLE variable)
{
	if (*(volatile PVOID *)&variable->Ptr)
		RtlWakeAllConditionVariable(variable);
}

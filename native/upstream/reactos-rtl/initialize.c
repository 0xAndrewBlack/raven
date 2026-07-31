#include <rtl.h>

BOOLEAN LdrpShutdownInProgress;
HANDLE LdrpShutdownThreadId;
static BOOLEAN initialized;
VOID NTAPI RtlpInitDeferredCriticalSection(VOID);
VOID NTAPI RtlInitializeHeapManager(VOID);

NTSTATUS NTAPI RavenInitializeRTL(PVOID *heaps, ULONG capacity)
{
	PPEB peb=NtCurrentPeb();
	if (initialized || !heaps || !capacity || capacity>512 || peb->ProcessHeaps!=heaps ||
		peb->MaximumNumberOfHeaps!=capacity || peb->NumberOfHeaps || peb->ProcessHeap || peb->NtGlobalFlag)
		return STATUS_INVALID_PARAMETER;
	RtlpInitDeferredCriticalSection();
	RtlInitializeHeapManager();
	initialized=TRUE;
	return STATUS_SUCCESS;
}

PVOID NTAPI RavenCreateHeap(ULONG flags, PVOID base, SIZE_T reserve, SIZE_T commit,
	PVOID lock, PRTL_HEAP_PARAMETERS parameters)
{
	PPEB peb=NtCurrentPeb();
	if (!initialized || (flags & ~7U) || peb->NtGlobalFlag) {
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NOT_SUPPORTED);
		return NULL;
	}
	if (peb->NumberOfHeaps>=peb->MaximumNumberOfHeaps) {
		RtlSetLastWin32ErrorAndNtStatusFromNtStatus(STATUS_NO_MEMORY);
		if (flags & HEAP_GENERATE_EXCEPTIONS) RtlRaiseStatus(STATUS_NO_MEMORY);
		return NULL;
	}
	return RtlCreateHeap(flags,base,reserve,commit,lock,parameters);
}

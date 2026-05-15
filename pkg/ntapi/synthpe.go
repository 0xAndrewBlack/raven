//go:build guest_windows

package ntapi

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/mirkobrombin/Raven/pkg/loader"
	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// PE section characteristics (duplicated from loader for use in synth PE gen).
const (
	imageScnMemExecute = 0x20000000
	imageScnMemRead    = 0x40000000
	imageScnCntCode    = 0x00000020
)

// VM_TRAP_INSTRUCTION: vmcall (0x0F 0x01 0xC1) - 3 bytes, triggers our Go handler.
var vmTrapBytes = []byte{0x0F, 0x01, 0xC1}

// SynthPE builds a minimal PE image in guest memory with an export table
// where every export is a trap stub: mov eax, <id>; vmcall; ret.
type SynthPE struct {
	Name       string
	BaseAddr   uint64
	ImageSize  uint64
	Exports    map[string]uint64 // name → guest address of stub
	StubIDs    map[uint64]uint32 // guest address → syscall ID
	ExportOrds map[uint16]uint64 // export ordinal → guest address of stub
}

var knownSynthOrdinals = map[string]map[string]uint16{
	"uxtheme.dll": {
		"OpenNcThemeData":                      49,
		"RefreshImmersiveColorPolicyState":     104,
		"GetIsImmersiveColorUsingHighContrast": 106,
		"ShouldAppsUseDarkMode":                132,
		"AllowDarkModeForWindow":               133,
		"SetPreferredAppMode":                  135,
		"FlushMenuThemes":                      136,
		"IsDarkModeAllowedForWindow":           137,
		"ShouldSystemUseDarkMode":              138,
	},
}

func bindKnownSynthOrdinal(synth *SynthPE, funcName string, addr uint64) {
	if synth == nil || addr == 0 {
		return
	}
	if ordinal, ok := knownSynthOrdinals[strings.ToLower(synth.Name)][funcName]; ok {
		synth.ExportOrds[ordinal] = addr
	}
}

// AddDynamicExport allocates a new trap stub in guest memory and
// registers it in the synth's export map. Returns the syscall ID
// for handler registration, or 0 if the function already exists.
func (s *SynthPE) AddDynamicExport(mem *mmu.MMU, funcName string, id uint32) uint32 {
	if _, ok := s.Exports[funcName]; ok {
		return 0 // already exists
	}
	// Allocate a new page for the stub (simple approach: each dynamic export gets its own mmap)
	stubAddr := mem.Mmap(0, stubSize, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	// Write trap stub: mov eax, <id>; vmcall; ret
	buf := make([]byte, stubSize)
	buf[0] = 0xB8 // MOV EAX, imm32
	binary.LittleEndian.PutUint32(buf[1:5], id)
	copy(buf[5:8], vmTrapBytes)
	buf[8] = 0xC3 // RET
	for i := 9; i < int(stubSize); i++ {
		buf[i] = 0xCC // INT3
	}
	mem.WriteBytes(stubAddr, buf)
	s.Exports[funcName] = stubAddr
	s.StubIDs[stubAddr] = id
	bindKnownSynthOrdinal(s, funcName, stubAddr)
	return id
}

// PatchStub replaces a function's stub with custom x64 machine code.
// The code must fit within stubSize bytes. Returns false if the function
// is not found or the code is too large.
func (s *SynthPE) PatchStub(mem *mmu.MMU, funcName string, code []byte) bool {
	addr, ok := s.Exports[funcName]
	if !ok {
		return false
	}
	if len(code) > int(stubSize) {
		return false
	}
	// Write the custom code
	mem.WriteBytes(addr, code)
	// Fill remaining bytes with INT3 (0xCC) for safety
	for i := len(code); i < int(stubSize); i++ {
		mem.Write8(addr+uint64(i), 0xCC)
	}
	// Remove from StubIDs so the dispatcher doesn't try to handle it
	delete(s.StubIDs, addr)
	return true
}

// ntapiExports lists all NTAPI functions exported by the synthetic ntdll.dll.
// This covers every import that Wine's kernel32, kernelbase, user32, gdi32,
// comctl32, advapi32, ucrtbase, sechost, msvcrt, imm32, and rpcrt4 need.
var ntapiExports = []string{
	// ── Nt* syscalls (157) ──
	"NtAcceptConnectPort",
	"NtAccessCheck",
	"NtAddAtom",
	"NtAdjustGroupsToken",
	"NtAdjustPrivilegesToken",
	"NtAlertResumeThread",
	"NtAlertThread",
	"NtAllocateLocallyUniqueId",
	"NtAllocateUuids",
	"NtAllocateVirtualMemory",
	"NtAllocateVirtualMemoryEx",
	"NtAreMappedFilesTheSame",
	"NtAssignProcessToJobObject",
	"NtCallbackReturn",
	"NtCancelIoFile",
	"NtCancelIoFileEx",
	"NtCancelSynchronousIoFile",
	"NtCancelTimer",
	"NtClearEvent",
	"NtClose",
	"NtCompareObjects",
	"NtCreateDirectoryObject",
	"NtCreateEvent",
	"NtCreateFile",
	"NtCreateIoCompletion",
	"NtCreateJobObject",
	"NtCreateKey",
	"NtCreateKeyedEvent",
	"NtCreateMailslotFile",
	"NtCreateMutant",
	"NtCreateNamedPipeFile",
	"NtCreateSection",
	"NtCreateSemaphore",
	"NtCreateSymbolicLinkObject",
	"NtCreateThread",
	"NtCreateThreadEx",
	"NtCreateTimer",
	"NtCreateUserProcess",
	"NtDelayExecution",
	"NtDeleteAtom",
	"NtDeleteFile",
	"NtDeleteKey",
	"NtDeleteValueKey",
	"NtDeviceIoControlFile",
	"NtDuplicateObject",
	"NtDuplicateToken",
	"NtEnumerateKey",
	"NtEnumerateValueKey",
	"NtFilterToken",
	"NtFindAtom",
	"NtFlushBuffersFile",
	"NtFlushInstructionCache",
	"NtFlushKey",
	"NtFlushVirtualMemory",
	"NtFreeVirtualMemory",
	"NtFsControlFile",
	"NtGetContextThread",
	"NtGetNlsSectionPtr",
	"NtGetTickCount",
	"NtGetWriteWatch",
	"NtImpersonateAnonymousToken",
	"NtIsProcessInJob",
	"NtLoadKey",
	"NtLockFile",
	"NtLockVirtualMemory",
	"NtMakeTemporaryObject",
	"NtMapViewOfSection",
	"NtMapViewOfSectionEx",
	"NtNotifyChangeDirectoryFile",
	"NtNotifyChangeKey",
	"NtOpenDirectoryObject",
	"NtOpenEvent",
	"NtOpenFile",
	"NtOpenJobObject",
	"NtOpenKey",
	"NtOpenKeyEx",
	"NtOpenKeyedEvent",
	"NtOpenMutant",
	"NtOpenProcess",
	"NtOpenProcessToken",
	"NtOpenSection",
	"NtOpenSemaphore",
	"NtOpenSymbolicLinkObject",
	"NtOpenThread",
	"NtOpenThreadToken",
	"NtOpenTimer",
	"NtPowerInformation",
	"NtPrivilegeCheck",
	"NtProtectVirtualMemory",
	"NtPulseEvent",
	"NtQueryAttributesFile",
	"NtQueryDefaultLocale",
	"NtQueryDefaultUILanguage",
	"NtQueryDirectoryFile",
	"NtQueryDirectoryFileEx",
	"NtQueryDirectoryObject",
	"NtQueryFullAttributesFile",
	"NtQueryInformationAtom",
	"NtQueryInformationFile",
	"NtQueryInformationJobObject",
	"NtQueryInformationProcess",
	"NtQueryInformationThread",
	"NtQueryInformationToken",
	"NtQueryInstallUILanguage",
	"NtQueryKey",
	"NtQueryMutant",
	"NtQueryEvent",
	"NtQueryObject",
	"NtQueryPerformanceCounter",
	"NtQuerySection",
	"NtQuerySecurityObject",
	"NtQuerySemaphore",
	"NtQuerySymbolicLinkObject",
	"NtQuerySystemInformation",
	"NtQuerySystemInformationEx",
	"NtQuerySystemTime",
	"NtQueryTimer",
	"NtQueryTimerResolution",
	"NtQueryValueKey",
	"NtQueryVirtualMemory",
	"NtQueryVolumeInformationFile",
	"NtQueueApcThread",
	"NtReadFile",
	"NtReadFileScatter",
	"NtReadVirtualMemory",
	"NtReleaseMutant",
	"NtReleaseKeyedEvent",
	"NtReleaseSemaphore",
	"NtRemoveIoCompletion",
	"NtRemoveIoCompletionEx",
	"NtRenameKey",
	"NtResetEvent",
	"NtResetWriteWatch",
	"NtResumeThread",
	"NtSaveKey",
	"NtSetContextThread",
	"NtSetEvent",
	"NtSetInformationDebugObject",
	"NtSetInformationFile",
	"NtSetInformationJobObject",
	"NtSetInformationObject",
	"NtSetInformationProcess",
	"NtSetInformationThread",
	"NtSetInformationToken",
	"NtSetInformationVirtualMemory",
	"NtSetIoCompletion",
	"NtSetSecurityObject",
	"NtSetSystemInformation",
	"NtSetSystemTime",
	"NtSetThreadExecutionState",
	"NtSetTimer",
	"NtSetTimerEx",
	"NtSetValueKey",
	"NtSignalAndWaitForSingleObject",
	"NtSuspendThread",
	"NtTerminateJobObject",
	"NtTerminateProcess",
	"NtTerminateThread",
	"NtTestAlert",
	"NtUnloadKey",
	"NtUnlockFile",
	"NtUnlockVirtualMemory",
	"NtUnmapViewOfSection",
	"NtUnmapViewOfSectionEx",
	"NtWaitForKeyedEvent",
	"NtWaitForMultipleObjects",
	"NtWaitForSingleObject",
	"NtWriteFile",
	"NtWriteFileGather",
	"NtWriteVirtualMemory",
	"NtYieldExecution",
	// Zw* aliases for key NT functions
	"ZwAllocateUuids",
	"ZwCreateKeyedEvent",
	"ZwOpenKeyedEvent",
	"ZwReleaseKeyedEvent",
	"ZwTerminateThread",
	"ZwWaitForKeyedEvent",

	// ── Rtl* runtime library (259) ──
	"RtlAcquirePebLock",
	"RtlAcquireSRWLockExclusive",
	"RtlAcquireSRWLockShared",
	"RtlActivateActivationContext",
	"RtlAddAccessAllowedAce",
	"RtlAddAccessAllowedAceEx",
	"RtlAddAccessAllowedObjectAce",
	"RtlAddAccessDeniedAce",
	"RtlAddAccessDeniedAceEx",
	"RtlAddAccessDeniedObjectAce",
	"RtlAddAce",
	"RtlAddAtomToAtomTable",
	"RtlAddAuditAccessAce",
	"RtlAddAuditAccessAceEx",
	"RtlAddAuditAccessObjectAce",
	"RtlAddFunctionTable",
	"RtlAddGrowableFunctionTable",
	"RtlAddMandatoryAce",
	"RtlAddRefActivationContext",
	"RtlAddVectoredExceptionHandler",
	"RtlAllocateAndInitializeSid",
	"RtlAllocateHeap",
	"RtlAnsiStringToUnicodeString",
	"RtlAreAllAccessesGranted",
	"RtlAreAnyAccessesGranted",
	"RtlAreBitsClear",
	"RtlAreBitsSet",
	"RtlCaptureContext",
	"RtlCharToInteger",
	"RtlClearBits",
	"RtlCompactHeap",
	"RtlCompareUnicodeString",
	"RtlCompareUnicodeStrings",
	"RtlConvertSidToUnicodeString",
	"RtlConvertToAutoInheritSecurityObject",
	"RtlCopyContext",
	"RtlCopySid",
	"RtlCopyUnicodeString",
	"RtlCreateAcl",
	"RtlCreateActivationContext",
	"RtlCreateAtomTable",
	"RtlCreateEnvironment",
	"RtlCreateHeap",
	"RtlCreateProcessParameters",
	"RtlCreateProcessParametersEx",
	"RtlCreateSecurityDescriptor",
	"RtlCreateTimer",
	"RtlCreateTimerQueue",
	"RtlCreateUnicodeString",
	"RtlCreateUnicodeStringFromAsciiz",
	"RtlCreateUserStack",
	"RtlCreateUserThread",
	"RtlDeactivateActivationContext",
	"RtlDecodePointer",
	"RtlDecodeSystemPointer",
	"RtlDeleteAce",
	"RtlDeleteAtomFromAtomTable",
	"RtlDeleteCriticalSection",
	"RtlDeleteFunctionTable",
	"RtlDeleteGrowableFunctionTable",
	"RtlDeleteSecurityObject",
	"RtlDeleteTimer",
	"RtlDeleteTimerQueueEx",
	"RtlDeregisterWait",
	"RtlDeregisterWaitEx",
	"RtlDestroyAtomTable",
	"RtlDestroyEnvironment",
	"RtlDestroyHeap",
	"RtlDestroyProcessParameters",
	"RtlDetermineDosPathNameType_U",
	"RtlDoesFileExists_U",
	"RtlDosPathNameToNtPathName_U",
	"RtlDosPathNameToNtPathName_U_WithStatus",
	"RtlDosSearchPath_U",
	"RtlDowncaseUnicodeChar",
	"RtlDowncaseUnicodeString",
	"RtlDuplicateUnicodeString",
	"RtlEnterCriticalSection",
	"RtlEqualPrefixSid",
	"RtlEqualSid",
	"RtlEncodePointer",
	"RtlEncodeSystemPointer",
	"RtlExitUserProcess",
	"RtlExitUserThread",
	"RtlExpandEnvironmentStrings_U",
	"RtlFindActivationContextSectionGuid",
	"RtlFindActivationContextSectionString",
	"RtlFindClearBitsAndSet",
	"RtlFindMessage",
	"RtlFirstFreeAce",
	"RtlFlsAlloc",
	"RtlFlsFree",
	"RtlFlsGetValue",
	"RtlFlsSetValue",
	"RtlFormatMessage",
	"RtlFreeActivationContextStack",
	"RtlFreeAnsiString",
	"RtlFreeHeap",
	"RtlFreeSid",
	"RtlFreeUnicodeString",
	"RtlFreeUserStack",
	"RtlGUIDFromString",
	"RtlGetAce",
	"RtlGetActiveActivationContext",
	"RtlGetControlSecurityDescriptor",
	"RtlGetCurrentDirectory_U",
	"RtlGetCurrentPeb",
	"RtlGetDaclSecurityDescriptor",
	"RtlGetEnabledExtendedFeatures",
	"RtlGetExePath",
	"RtlGetExtendedContextLength2",
	"RtlGetExtendedFeaturesMask",
	"RtlGetFullPathName_U",
	"RtlGetGroupSecurityDescriptor",
	"RtlGetLastWin32Error",
	"RtlGetLocaleFileMappingAddress",
	"RtlGetNativeSystemInformation",
	"RtlGetNtGlobalFlags",
	"RtlGetNtVersionNumbers",
	"RtlGetNtProductType",
	"RtlGetOwnerSecurityDescriptor",
	"RtlGetProcessHeaps",
	"RtlGetProcessPreferredUILanguages",
	"RtlGetProductInfo",
	"RtlGetSaclSecurityDescriptor",
	"RtlGetSearchPath",
	"RtlGetSystemPreferredUILanguages",
	"RtlGetSystemTimePrecise",
	"RtlGetThreadErrorMode",
	"RtlGetThreadPreferredUILanguages",
	"RtlGetUserInfoHeap",
	"RtlGetUserPreferredUILanguages",
	"RtlGetVersion",
	"RtlGrowFunctionTable",
	"RtlIdentifierAuthoritySid",
	"RtlIdnToAscii",
	"RtlIdnToNameprepUnicode",
	"RtlIdnToUnicode",
	"RtlImageDirectoryEntryToData",
	"RtlImageNtHeader",
	"RtlImageRvaToVa",
	"RtlImpersonateSelf",
	"RtlInitAnsiString",
	"RtlInitCodePageTable",
	"RtlInitNlsTables",
	"RtlInitUnicodeString",
	"RtlInitUnicodeStringEx",
	"RtlInitializeBitMap",
	"RtlInitializeConditionVariable",
	"RtlInitializeCriticalSection",
	"RtlInitializeCriticalSectionAndSpinCount",
	"RtlInitializeCriticalSectionEx",
	"RtlInitializeExtendedContext2",
	"RtlInitializeSRWLock",
	"RtlInitializeSListHead",
	"RtlInitializeSid",
	"RtlInstallFunctionTableCallback",
	"RtlInterlockedFlushSList",
	"RtlInterlockedPopEntrySList",
	"RtlInterlockedPushEntrySList",
	"RtlQueryDepthSList",
	"RtlIsDosDeviceName_U",
	"RtlIsNameLegalDOS8Dot3",
	"RtlIsNormalizedString",
	"RtlIsProcessorFeaturePresent",
	"RtlIsTextUnicode",
	"RtlLeaveCriticalSection",
	"RtlLengthRequiredSid",
	"RtlLengthSecurityDescriptor",
	"RtlLengthSid",
	"RtlLocalTimeToSystemTime",
	"RtlLocateExtendedFeature",
	"RtlLockHeap",
	"RtlLookupAtomInAtomTable",
	"RtlLookupFunctionEntry",
	"RtlMakeSelfRelativeSD",
	"RtlMapGenericMask",
	"RtlMultiByteToUnicodeN",
	"RtlMultiByteToUnicodeSize",
	"RtlNewSecurityObject",
	"RtlNewSecurityObjectEx",
	"RtlNewSecurityObjectWithMultipleInheritance",
	"RtlNormalizeProcessParams",
	"RtlNormalizeString",
	"RtlNtStatusToDosError",
	"RtlOemStringToUnicodeString",
	"RtlOpenCurrentUser",
	"RtlPcToFileHeader",
	"RtlProcessFlsData",
	"RtlQueryActivationContextApplicationSettings",
	"RtlQueryAtomInAtomTable",
	"RtlQueryDynamicTimeZoneInformation",
	"RtlQueryEnvironmentVariable_U",
	"RtlQueryHeapInformation",
	"RtlQueryInformationAcl",
	"RtlQueryInformationActivationContext",
	"RtlQueryPerformanceCounter",
	"RtlQueryPerformanceFrequency",
	"RtlQueryTimeZoneInformation",
	"RtlQueryUnbiasedInterruptTime",
	"RtlQueueWorkItem",
	"RtlRaiseException",
	"RtlRaiseStatus",
	"RtlRandom",
	"RtlReAllocateHeap",
	"RtlRegisterWait",
	"RtlReleaseActivationContext",
	"RtlReleasePath",
	"RtlReleasePebLock",
	"RtlReleaseSRWLockExclusive",
	"RtlReleaseSRWLockShared",
	"RtlRemoveVectoredExceptionHandler",
	"RtlResetRtlTranslations",
	"RtlRestoreContext",
	"RtlRunOnceBeginInitialize",
	"RtlRunOnceComplete",
	"RtlRunOnceExecuteOnce",
	"RtlSecondsSince1970ToTime",
	"RtlSelfRelativeToAbsoluteSD",
	"RtlSetBits",
	"RtlSetControlSecurityDescriptor",
	"RtlSetCurrentDirectory_U",
	"RtlSetCurrentEnvironment",
	"RtlSetDaclSecurityDescriptor",
	"RtlSetEnvironmentVariable",
	"RtlSetExtendedFeaturesMask",
	"RtlSetGroupSecurityDescriptor",
	"RtlSetHeapInformation",
	"RtlSetIoCompletionCallback",
	"RtlSetLastWin32Error",
	"RtlSetOwnerSecurityDescriptor",
	"RtlSetProcessPreferredUILanguages",
	"RtlSetSaclSecurityDescriptor",
	"RtlSetSearchPathMode",
	"RtlSetThreadErrorMode",
	"RtlSetThreadPreferredUILanguages",
	"RtlSetTimeZoneInformation",
	"RtlSetUnhandledExceptionFilter",
	"RtlSetUserValueHeap",
	"RtlSizeHeap",
	"RtlSleepConditionVariableCS",
	"RtlSleepConditionVariableSRW",
	"RtlSubAuthorityCountSid",
	"RtlSubAuthoritySid",
	"RtlSystemTimeToLocalTime",
	"RtlTimeFieldsToTime",
	"RtlTimeToSecondsSince1970",
	"RtlTimeToTimeFields",
	"RtlTryAcquireSRWLockExclusive",
	"RtlTryAcquireSRWLockShared",
	"RtlTryEnterCriticalSection",
	"RtlUTF8ToUnicodeN",
	"RtlUnicodeStringToAnsiSize",
	"RtlUnicodeStringToAnsiString",
	"RtlUnicodeStringToInteger",
	"RtlUnicodeStringToOemSize",
	"RtlUnicodeStringToOemString",
	"RtlUnicodeToMultiByteN",
	"RtlUnicodeToMultiByteSize",
	"RtlUnicodeToOemN",
	"RtlUnicodeToUTF8N",
	"RtlUniform",
	"RtlUnlockHeap",
	"RtlUnwind",
	"RtlUnwindEx",
	"RtlUpcaseUnicodeString",
	"RtlUpdateTimer",
	"RtlUpperChar",
	"RtlValidAcl",
	"RtlValidSecurityDescriptor",
	"RtlValidSid",
	"RtlValidateHeap",
	"RtlVirtualUnwind",
	"RtlWaitOnAddress",
	"RtlWakeAllConditionVariable",
	"RtlWakeConditionVariable",
	"RtlWalkHeap",
	"RtlWow64EnableFsRedirection",
	"RtlWow64EnableFsRedirectionEx",
	"RtlWow64GetProcessMachines",
	"RtlWow64GetThreadContext",
	"RtlWow64SetThreadContext",
	"RtlZombifyActivationContext",

	// ── Ldr* loader (22) ──
	"LdrAccessResource",
	"LdrAddDllDirectory",
	"LdrAddRefDll",
	"LdrDisableThreadCalloutsForDll",
	"LdrFindResourceDirectory_U",
	"LdrFindResource_U",
	"LdrGetDllDirectory",
	"LdrGetDllFullName",
	"LdrGetDllHandle",
	"LdrGetDllHandleEx",
	"LdrGetDllPath",
	"LdrGetProcedureAddress",
	"LdrInitializeThunk",
	"LdrLoadDll",
	"LdrQueryImageFileExecutionOptions",
	"LdrRemoveDllDirectory",
	"LdrResolveDelayLoadedAPI",
	"LdrSetDefaultDllDirectories",
	"LdrSetDllDirectory",
	"LdrShutdownProcess",
	"LdrShutdownThread",
	"LdrUnloadDll",

	// ── Tp* thread pool (10) ──
	"TpAllocCleanupGroup",
	"TpAllocIoCompletion",
	"TpAllocPool",
	"TpAllocTimer",
	"TpAllocWait",
	"TpAllocWork",
	"TpCallbackMayRunLong",
	"TpQueryPoolStackInformation",
	"TpSetPoolStackInformation",
	"TpSimpleTryPost",

	// ── Dbg* debugging (9) ──
	"DbgBreakPoint",
	"DbgUiConnectToDbg",
	"DbgUiContinue",
	"DbgUiConvertStateChangeStructure",
	"DbgUiDebugActiveProcess",
	"DbgUiGetThreadDebugObject",
	"DbgUiIssueRemoteBreakin",
	"DbgUiStopDebugging",
	"DbgUiWaitStateChange",

	// ── Etw* event tracing (12) ──
	"EtwEventActivityIdControl",
	"EtwEventEnabled",
	"EtwEventProviderEnabled",
	"EtwEventRegister",
	"EtwEventSetInformation",
	"EtwEventUnregister",
	"EtwEventWrite",
	"EtwEventWriteString",
	"EtwEventWriteTransfer",
	"EtwGetTraceEnableFlags",
	"EtwGetTraceEnableLevel",
	"EtwGetTraceLoggerHandle",

	// ── Wine debug channel stubs ──
	"__wine_dbg_get_channel_flags",
	"__wine_dbg_header",
	"__wine_dbg_output",
	"__wine_dbg_strdup",

	// ── Wine helper functions ──
	"wine_get_host_version",
	"wine_get_version",
	"wine_nt_to_unix_file_name",
	"wine_server_call",
	"wine_unix_to_nt_file_name",

	// ── C runtime functions exported by ntdll (42) ──
	"ApiSetQueryApiSetPresenceEx",
	"MD4Final",
	"MD4Init",
	"MD4Update",
	"_strnicmp",
	"_vsnprintf",
	"_vsnwprintf",
	"_wcsicmp",
	"_wcsnicmp",
	"isalnum",
	"isalpha",
	"islower",
	"isxdigit",
	"memcmp",
	"memcpy",
	"memmove",
	"memset",
	"strcat",
	"strchr",
	"strcmp",
	"strcpy",
	"strlen",
	"strncmp",
	"strpbrk",
	"strrchr",
	"strtol",
	"tolower",
	"towupper",
	"wcscat",
	"wcschr",
	"wcscmp",
	"wcscpy",
	"wcscspn",
	"wcslen",
	"wcsncmp",
	"wcsnlen",
	"wcspbrk",
	"wcsrchr",
	"wcsspn",
	"wcsstr",
	"wcstol",
	"wcstoul",

	// Hardware resource descriptor helpers
	"RtlCmDecodeMemIoResource",
	"RtlIoDecodeMemIoResource",
}

// win32uExports lists Win32k (NtGdi*/NtUser*) syscall stubs in the ReactOS
// win32k SSDT order, generated from win32ss/w32ksvc32.h ("Windows 2003 SP2"
// service ordering). A real ReactOS gdi32/user32 issuing
//
//	mov eax,<svc#>; mov edx,0x7FFE0300; call [edx]
//
// thus resolves to the correct service: number = win32uIDBase(0x1000) + index.
// The first 738 entries are the pinned ReactOS table; any trailing entries are
// Raven extras not present in that table (e.g. Win10 NtUserGetSystemDpiForProcess).
var win32uExports = []string{
	"NtGdiAbortDoc",
	"NtGdiAbortPath",
	"NtGdiAddFontResourceW",
	"NtGdiAddRemoteFontToDC",
	"NtGdiAddFontMemResourceEx",
	"NtGdiRemoveMergeFont",
	"NtGdiAddRemoteMMInstanceToDC",
	"NtGdiAlphaBlend",
	"NtGdiAngleArc",
	"NtGdiAnyLinkedFonts",
	"NtGdiFontIsLinked",
	"NtGdiArcInternal",
	"NtGdiBeginPath",
	"NtGdiBitBlt",
	"NtGdiCancelDC",
	"NtGdiCheckBitmapBits",
	"NtGdiCloseFigure",
	"NtGdiClearBitmapAttributes",
	"NtGdiClearBrushAttributes",
	"NtGdiColorCorrectPalette",
	"NtGdiCombineRgn",
	"NtGdiCombineTransform",
	"NtGdiComputeXformCoefficients",
	"NtGdiConsoleTextOut",
	"NtGdiConvertMetafileRect",
	"NtGdiCreateBitmap",
	"NtGdiCreateClientObj",
	"NtGdiCreateColorSpace",
	"NtGdiCreateColorTransform",
	"NtGdiCreateCompatibleBitmap",
	"NtGdiCreateCompatibleDC",
	"NtGdiCreateDIBBrush",
	"NtGdiCreateDIBitmapInternal",
	"NtGdiCreateDIBSection",
	"NtGdiCreateEllipticRgn",
	"NtGdiCreateHalftonePalette",
	"NtGdiCreateHatchBrushInternal",
	"NtGdiCreateMetafileDC",
	"NtGdiCreatePaletteInternal",
	"NtGdiCreatePatternBrushInternal",
	"NtGdiCreatePen",
	"NtGdiCreateRectRgn",
	"NtGdiCreateRoundRectRgn",
	"NtGdiCreateServerMetaFile",
	"NtGdiCreateSolidBrush",
	"NtGdiD3dContextCreate",
	"NtGdiD3dContextDestroy",
	"NtGdiD3dContextDestroyAll",
	"NtGdiD3dValidateTextureStageState",
	"NtGdiD3dDrawPrimitives2",
	"NtGdiDdGetDriverState",
	"NtGdiDdAddAttachedSurface",
	"NtGdiDdAlphaBlt",
	"NtGdiDdAttachSurface",
	"NtGdiDdBeginMoCompFrame",
	"NtGdiDdBlt",
	"NtGdiDdCanCreateSurface",
	"NtGdiDdCanCreateD3DBuffer",
	"NtGdiDdColorControl",
	"NtGdiDdCreateDirectDrawObject",
	"NtGdiDdCreateSurface",
	"NtGdiDdCreateD3DBuffer",
	"NtGdiDdCreateMoComp",
	"NtGdiDdCreateSurfaceObject",
	"NtGdiDdDeleteDirectDrawObject",
	"NtGdiDdDeleteSurfaceObject",
	"NtGdiDdDestroyMoComp",
	"NtGdiDdDestroySurface",
	"NtGdiDdDestroyD3DBuffer",
	"NtGdiDdEndMoCompFrame",
	"NtGdiDdFlip",
	"NtGdiDdFlipToGDISurface",
	"NtGdiDdGetAvailDriverMemory",
	"NtGdiDdGetBltStatus",
	"NtGdiDdGetDC",
	"NtGdiDdGetDriverInfo",
	"NtGdiDdGetDxHandle",
	"NtGdiDdGetFlipStatus",
	"NtGdiDdGetInternalMoCompInfo",
	"NtGdiDdGetMoCompBuffInfo",
	"NtGdiDdGetMoCompGuids",
	"NtGdiDdGetMoCompFormats",
	"NtGdiDdGetScanLine",
	"NtGdiDdLock",
	"NtGdiDdLockD3D",
	"NtGdiDdQueryDirectDrawObject",
	"NtGdiDdQueryMoCompStatus",
	"NtGdiDdReenableDirectDrawObject",
	"NtGdiDdReleaseDC",
	"NtGdiDdRenderMoComp",
	"NtGdiDdResetVisrgn",
	"NtGdiDdSetColorKey",
	"NtGdiDdSetExclusiveMode",
	"NtGdiDdSetGammaRamp",
	"NtGdiDdCreateSurfaceEx",
	"NtGdiDdSetOverlayPosition",
	"NtGdiDdUnattachSurface",
	"NtGdiDdUnlock",
	"NtGdiDdUnlockD3D",
	"NtGdiDdUpdateOverlay",
	"NtGdiDdWaitForVerticalBlank",
	"NtGdiDvpCanCreateVideoPort",
	"NtGdiDvpColorControl",
	"NtGdiDvpCreateVideoPort",
	"NtGdiDvpDestroyVideoPort",
	"NtGdiDvpFlipVideoPort",
	"NtGdiDvpGetVideoPortBandwidth",
	"NtGdiDvpGetVideoPortField",
	"NtGdiDvpGetVideoPortFlipStatus",
	"NtGdiDvpGetVideoPortInputFormats",
	"NtGdiDvpGetVideoPortLine",
	"NtGdiDvpGetVideoPortOutputFormats",
	"NtGdiDvpGetVideoPortConnectInfo",
	"NtGdiDvpGetVideoSignalStatus",
	"NtGdiDvpUpdateVideoPort",
	"NtGdiDvpWaitForVideoPortSync",
	"NtGdiDvpAcquireNotification",
	"NtGdiDvpReleaseNotification",
	"NtGdiDxgGenericThunk",
	"NtGdiDeleteClientObj",
	"NtGdiDeleteColorSpace",
	"NtGdiDeleteColorTransform",
	"NtGdiDeleteObjectApp",
	"NtGdiDescribePixelFormat",
	"NtGdiGetPerBandInfo",
	"NtGdiDoBanding",
	"NtGdiDoPalette",
	"NtGdiDrawEscape",
	"NtGdiEllipse",
	"NtGdiEnableEudc",
	"NtGdiEndDoc",
	"NtGdiEndPage",
	"NtGdiEndPath",
	"NtGdiEnumFontChunk",
	"NtGdiEnumFontClose",
	"NtGdiEnumFontOpen",
	"NtGdiEnumObjects",
	"NtGdiEqualRgn",
	"NtGdiEudcLoadUnloadLink",
	"NtGdiExcludeClipRect",
	"NtGdiExtCreatePen",
	"NtGdiExtCreateRegion",
	"NtGdiExtEscape",
	"NtGdiExtFloodFill",
	"NtGdiExtGetObjectW",
	"NtGdiExtSelectClipRgn",
	"NtGdiExtTextOutW",
	"NtGdiFillPath",
	"NtGdiFillRgn",
	"NtGdiFlattenPath",
	"NtGdiFlush",
	"NtGdiForceUFIMapping",
	"NtGdiFrameRgn",
	"NtGdiFullscreenControl",
	"NtGdiGetAndSetDCDword",
	"NtGdiGetAppClipBox",
	"NtGdiGetBitmapBits",
	"NtGdiGetBitmapDimension",
	"NtGdiGetBoundsRect",
	"NtGdiGetCharABCWidthsW",
	"NtGdiGetCharacterPlacementW",
	"NtGdiGetCharSet",
	"NtGdiGetCharWidthW",
	"NtGdiGetCharWidthInfo",
	"NtGdiGetColorAdjustment",
	"NtGdiGetColorSpaceforBitmap",
	"NtGdiGetDCDword",
	"NtGdiGetDCforBitmap",
	"NtGdiGetDCObject",
	"NtGdiGetDCPoint",
	"NtGdiGetDeviceCaps",
	"NtGdiGetDeviceGammaRamp",
	"NtGdiGetDeviceCapsAll",
	"NtGdiGetDIBitsInternal",
	"NtGdiGetETM",
	"NtGdiGetEudcTimeStampEx",
	"NtGdiGetFontData",
	"NtGdiGetFontResourceInfoInternalW",
	"NtGdiGetGlyphIndicesW",
	"NtGdiGetGlyphIndicesWInternal",
	"NtGdiGetGlyphOutline",
	"NtGdiGetKerningPairs",
	"NtGdiGetLinkedUFIs",
	"NtGdiGetMiterLimit",
	"NtGdiGetMonitorID",
	"NtGdiGetNearestColor",
	"NtGdiGetNearestPaletteIndex",
	"NtGdiGetObjectBitmapHandle",
	"NtGdiGetOutlineTextMetricsInternalW",
	"NtGdiGetPath",
	"NtGdiGetPixel",
	"NtGdiGetRandomRgn",
	"NtGdiGetRasterizerCaps",
	"NtGdiGetRealizationInfo",
	"NtGdiGetRegionData",
	"NtGdiGetRgnBox",
	"NtGdiGetServerMetaFileBits",
	"NtGdiGetSpoolMessage",
	"NtGdiGetStats",
	"NtGdiGetStockObject",
	"NtGdiGetStringBitmapW",
	"NtGdiGetSystemPaletteUse",
	"NtGdiGetTextCharsetInfo",
	"NtGdiGetTextExtent",
	"NtGdiGetTextExtentExW",
	"NtGdiGetTextFaceW",
	"NtGdiGetTextMetricsW",
	"NtGdiGetTransform",
	"NtGdiGetUFI",
	"NtGdiGetEmbUFI",
	"NtGdiGetUFIPathname",
	"NtGdiGetEmbedFonts",
	"NtGdiChangeGhostFont",
	"NtGdiAddEmbFontToDC",
	"NtGdiGetFontUnicodeRanges",
	"NtGdiGetWidthTable",
	"NtGdiGradientFill",
	"NtGdiHfontCreate",
	"NtGdiIcmBrushInfo",
	"NtGdiInit",
	"NtGdiInitSpool",
	"NtGdiIntersectClipRect",
	"NtGdiInvertRgn",
	"NtGdiLineTo",
	"NtGdiMakeFontDir",
	"NtGdiMakeInfoDC",
	"NtGdiMaskBlt",
	"NtGdiModifyWorldTransform",
	"NtGdiMonoBitmap",
	"NtGdiMoveTo",
	"NtGdiOffsetClipRgn",
	"NtGdiOffsetRgn",
	"NtGdiOpenDCW",
	"NtGdiPatBlt",
	"NtGdiPolyPatBlt",
	"NtGdiPathToRegion",
	"NtGdiPlgBlt",
	"NtGdiPolyDraw",
	"NtGdiPolyPolyDraw",
	"NtGdiPolyTextOutW",
	"NtGdiPtInRegion",
	"NtGdiPtVisible",
	"NtGdiQueryFonts",
	"NtGdiQueryFontAssocInfo",
	"NtGdiRectangle",
	"NtGdiRectInRegion",
	"NtGdiRectVisible",
	"NtGdiRemoveFontResourceW",
	"NtGdiRemoveFontMemResourceEx",
	"NtGdiResetDC",
	"NtGdiResizePalette",
	"NtGdiRestoreDC",
	"NtGdiRoundRect",
	"NtGdiSaveDC",
	"NtGdiScaleViewportExtEx",
	"NtGdiScaleWindowExtEx",
	"NtGdiSelectBitmap",
	"NtGdiSelectBrush",
	"NtGdiSelectClipPath",
	"NtGdiSelectFont",
	"NtGdiSelectPen",
	"NtGdiSetBitmapAttributes",
	"NtGdiSetBitmapBits",
	"NtGdiSetBitmapDimension",
	"NtGdiSetBoundsRect",
	"NtGdiSetBrushAttributes",
	"NtGdiSetBrushOrg",
	"NtGdiSetColorAdjustment",
	"NtGdiSetColorSpace",
	"NtGdiSetDeviceGammaRamp",
	"NtGdiSetDIBitsToDeviceInternal",
	"NtGdiSetFontEnumeration",
	"NtGdiSetFontXform",
	"NtGdiSetIcmMode",
	"NtGdiSetLinkedUFIs",
	"NtGdiSetMagicColors",
	"NtGdiSetMetaRgn",
	"NtGdiSetMiterLimit",
	"NtGdiGetDeviceWidth",
	"NtGdiMirrorWindowOrg",
	"NtGdiSetLayout",
	"NtGdiSetPixel",
	"NtGdiSetPixelFormat",
	"NtGdiSetRectRgn",
	"NtGdiSetSystemPaletteUse",
	"NtGdiSetTextJustification",
	"NtGdiSetupPublicCFONT",
	"NtGdiSetVirtualResolution",
	"NtGdiSetSizeDevice",
	"NtGdiStartDoc",
	"NtGdiStartPage",
	"NtGdiStretchBlt",
	"NtGdiStretchDIBitsInternal",
	"NtGdiStrokeAndFillPath",
	"NtGdiStrokePath",
	"NtGdiSwapBuffers",
	"NtGdiTransformPoints",
	"NtGdiTransparentBlt",
	"NtGdiUnloadPrinterDriver",
	"NtGdiUnmapMemFont",
	"NtGdiUnrealizeObject",
	"NtGdiUpdateColors",
	"NtGdiWidenPath",
	"NtUserActivateKeyboardLayout",
	"NtUserAlterWindowStyle",
	"NtUserAssociateInputContext",
	"NtUserAttachThreadInput",
	"NtUserBeginPaint",
	"NtUserBitBltSysBmp",
	"NtUserBlockInput",
	"NtUserBuildHimcList",
	"NtUserBuildHwndList",
	"NtUserBuildNameList",
	"NtUserBuildPropList",
	"NtUserCallHwnd",
	"NtUserCallHwndLock",
	"NtUserCallHwndOpt",
	"NtUserCallHwndParam",
	"NtUserCallHwndParamLock",
	"NtUserCallMsgFilter",
	"NtUserCallNextHookEx",
	"NtUserCallNoParam",
	"NtUserCallOneParam",
	"NtUserCallTwoParam",
	"NtUserChangeClipboardChain",
	"NtUserChangeDisplaySettings",
	"NtUserCheckImeHotKey",
	"NtUserCheckMenuItem",
	"NtUserChildWindowFromPointEx",
	"NtUserClipCursor",
	"NtUserCloseClipboard",
	"NtUserCloseDesktop",
	"NtUserCloseWindowStation",
	"NtUserConsoleControl",
	"NtUserConvertMemHandle",
	"NtUserCopyAcceleratorTable",
	"NtUserCountClipboardFormats",
	"NtUserCreateAcceleratorTable",
	"NtUserCreateCaret",
	"NtUserCreateDesktop",
	"NtUserCreateInputContext",
	"NtUserCreateLocalMemHandle",
	"NtUserCreateWindowEx",
	"NtUserCreateWindowStation",
	"NtUserDdeGetQualityOfService",
	"NtUserDdeInitialize",
	"NtUserDdeSetQualityOfService",
	"NtUserDeferWindowPos",
	"NtUserDefSetText",
	"NtUserDeleteMenu",
	"NtUserDestroyAcceleratorTable",
	"NtUserDestroyCursor",
	"NtUserDestroyInputContext",
	"NtUserDestroyMenu",
	"NtUserDestroyWindow",
	"NtUserDisableThreadIme",
	"NtUserDispatchMessage",
	"NtUserDragDetect",
	"NtUserDragObject",
	"NtUserDrawAnimatedRects",
	"NtUserDrawCaption",
	"NtUserDrawCaptionTemp",
	"NtUserDrawIconEx",
	"NtUserDrawMenuBarTemp",
	"NtUserEmptyClipboard",
	"NtUserEnableMenuItem",
	"NtUserEnableScrollBar",
	"NtUserEndDeferWindowPosEx",
	"NtUserEndMenu",
	"NtUserEndPaint",
	"NtUserEnumDisplayDevices",
	"NtUserEnumDisplayMonitors",
	"NtUserEnumDisplaySettings",
	"NtUserEvent",
	"NtUserExcludeUpdateRgn",
	"NtUserFillWindow",
	"NtUserFindExistingCursorIcon",
	"NtUserFindWindowEx",
	"NtUserFlashWindowEx",
	"NtUserGetAltTabInfo",
	"NtUserGetAncestor",
	"NtUserGetAppImeLevel",
	"NtUserGetAsyncKeyState",
	"NtUserGetAtomName",
	"NtUserGetCaretBlinkTime",
	"NtUserGetCaretPos",
	"NtUserGetClassInfo",
	"NtUserGetClassName",
	"NtUserGetClipboardData",
	"NtUserGetClipboardFormatName",
	"NtUserGetClipboardOwner",
	"NtUserGetClipboardSequenceNumber",
	"NtUserGetClipboardViewer",
	"NtUserGetClipCursor",
	"NtUserGetComboBoxInfo",
	"NtUserGetControlBrush",
	"NtUserGetControlColor",
	"NtUserGetCPD",
	"NtUserGetCursorFrameInfo",
	"NtUserGetCursorInfo",
	"NtUserGetDC",
	"NtUserGetDCEx",
	"NtUserGetDoubleClickTime",
	"NtUserGetForegroundWindow",
	"NtUserGetGuiResources",
	"NtUserGetGUIThreadInfo",
	"NtUserGetIconInfo",
	"NtUserGetIconSize",
	"NtUserGetImeHotKey",
	"NtUserGetImeInfoEx",
	"NtUserGetInternalWindowPos",
	"NtUserGetKeyboardLayoutList",
	"NtUserGetKeyboardLayoutName",
	"NtUserGetKeyboardState",
	"NtUserGetKeyNameText",
	"NtUserGetKeyState",
	"NtUserGetListBoxInfo",
	"NtUserGetMenuBarInfo",
	"NtUserGetMenuIndex",
	"NtUserGetMenuItemRect",
	"NtUserGetMessage",
	"NtUserGetMouseMovePointsEx",
	"NtUserGetObjectInformation",
	"NtUserGetOpenClipboardWindow",
	"NtUserGetPriorityClipboardFormat",
	"NtUserGetProcessWindowStation",
	"NtUserGetRawInputBuffer",
	"NtUserGetRawInputData",
	"NtUserGetRawInputDeviceInfo",
	"NtUserGetRawInputDeviceList",
	"NtUserGetRegisteredRawInputDevices",
	"NtUserGetScrollBarInfo",
	"NtUserGetSystemMenu",
	"NtUserGetThreadDesktop",
	"NtUserGetThreadState",
	"NtUserGetTitleBarInfo",
	"NtUserGetUpdateRect",
	"NtUserGetUpdateRgn",
	"NtUserGetWindowDC",
	"NtUserGetWindowPlacement",
	"NtUserGetWOWClass",
	"NtUserHardErrorControl",
	"NtUserHideCaret",
	"NtUserHiliteMenuItem",
	"NtUserImpersonateDdeClientWindow",
	"NtUserInitialize",
	"NtUserInitializeClientPfnArrays",
	"NtUserInitTask",
	"NtUserInternalGetWindowText",
	"NtUserInvalidateRect",
	"NtUserInvalidateRgn",
	"NtUserIsClipboardFormatAvailable",
	"NtUserKillTimer",
	"NtUserLoadKeyboardLayoutEx",
	"NtUserLockWindowStation",
	"NtUserLockWindowUpdate",
	"NtUserLockWorkStation",
	"NtUserMapVirtualKeyEx",
	"NtUserMenuItemFromPoint",
	"NtUserMessageCall",
	"NtUserMinMaximize",
	"NtUserMNDragLeave",
	"NtUserMNDragOver",
	"NtUserModifyUserStartupInfoFlags",
	"NtUserMoveWindow",
	"NtUserNotifyIMEStatus",
	"NtUserNotifyProcessCreate",
	"NtUserNotifyWinEvent",
	"NtUserOpenClipboard",
	"NtUserOpenDesktop",
	"NtUserOpenInputDesktop",
	"NtUserOpenWindowStation",
	"NtUserPaintDesktop",
	"NtUserPeekMessage",
	"NtUserPostMessage",
	"NtUserPostThreadMessage",
	"NtUserPrintWindow",
	"NtUserProcessConnect",
	"NtUserQueryInformationThread",
	"NtUserQueryInputContext",
	"NtUserQuerySendMessage",
	"NtUserQueryWindow",
	"NtUserRealChildWindowFromPoint",
	"NtUserRealInternalGetMessage",
	"NtUserRealWaitMessageEx",
	"NtUserRedrawWindow",
	"NtUserRegisterClassExWOW",
	"NtUserRegisterUserApiHook",
	"NtUserRegisterHotKey",
	"NtUserRegisterRawInputDevices",
	"NtUserRegisterTasklist",
	"NtUserRegisterWindowMessage",
	"NtUserRemoveMenu",
	"NtUserRemoveProp",
	"NtUserResolveDesktop",
	"NtUserResolveDesktopForWOW",
	"NtUserSBGetParms",
	"NtUserScrollDC",
	"NtUserScrollWindowEx",
	"NtUserSelectPalette",
	"NtUserSendInput",
	"NtUserSetActiveWindow",
	"NtUserSetAppImeLevel",
	"NtUserSetCapture",
	"NtUserSetClassLong",
	"NtUserSetClassWord",
	"NtUserSetClipboardData",
	"NtUserSetClipboardViewer",
	"NtUserSetConsoleReserveKeys",
	"NtUserSetCursor",
	"NtUserSetCursorContents",
	"NtUserSetCursorIconData",
	"NtUserSetFocus",
	"NtUserSetImeHotKey",
	"NtUserSetImeInfoEx",
	"NtUserSetImeOwnerWindow",
	"NtUserSetInformationProcess",
	"NtUserSetInformationThread",
	"NtUserSetInternalWindowPos",
	"NtUserSetKeyboardState",
	"NtUserSetLogonNotifyWindow",
	"NtUserSetMenu",
	"NtUserSetMenuContextHelpId",
	"NtUserSetMenuDefaultItem",
	"NtUserSetMenuFlagRtoL",
	"NtUserSetObjectInformation",
	"NtUserSetParent",
	"NtUserSetProcessWindowStation",
	"NtUserSetProp",
	"NtUserSetScrollInfo",
	"NtUserSetShellWindowEx",
	"NtUserSetSysColors",
	"NtUserSetSystemCursor",
	"NtUserSetSystemMenu",
	"NtUserSetSystemTimer",
	"NtUserSetThreadDesktop",
	"NtUserSetThreadLayoutHandles",
	"NtUserSetThreadState",
	"NtUserSetTimer",
	"NtUserSetWindowFNID",
	"NtUserSetWindowLong",
	"NtUserSetWindowLongPtr",
	"NtUserSetWindowPlacement",
	"NtUserSetWindowPos",
	"NtUserSetWindowRgn",
	"NtUserSetWindowsHookAW",
	"NtUserSetWindowsHookEx",
	"NtUserSetWindowStationUser",
	"NtUserSetWindowWord",
	"NtUserSetWinEventHook",
	"NtUserShowCaret",
	"NtUserShowScrollBar",
	"NtUserShowWindow",
	"NtUserShowWindowAsync",
	"NtUserSoundSentry",
	"NtUserSwitchDesktop",
	"NtUserSystemParametersInfo",
	"NtUserTestForInteractiveUser",
	"NtUserThunkedMenuInfo",
	"NtUserThunkedMenuItemInfo",
	"NtUserToUnicodeEx",
	"NtUserTrackMouseEvent",
	"NtUserTrackPopupMenuEx",
	"NtUserCalcMenuBar",
	"NtUserPaintMenuBar",
	"NtUserTranslateAccelerator",
	"NtUserTranslateMessage",
	"NtUserUnhookWindowsHookEx",
	"NtUserUnhookWinEvent",
	"NtUserUnloadKeyboardLayout",
	"NtUserUnlockWindowStation",
	"NtUserUnregisterClass",
	"NtUserUnregisterUserApiHook",
	"NtUserUnregisterHotKey",
	"NtUserUpdateInputContext",
	"NtUserUpdateInstance",
	"NtUserUpdateLayeredWindow",
	"NtUserGetLayeredWindowAttributes",
	"NtUserSetLayeredWindowAttributes",
	"NtUserUpdatePerUserSystemParameters",
	"NtUserUserHandleGrantAccess",
	"NtUserValidateHandleSecure",
	"NtUserValidateRect",
	"NtUserValidateTimerCallback",
	"NtUserVkKeyScanEx",
	"NtUserWaitForInputIdle",
	"NtUserWaitForMsgAndEvent",
	"NtUserWaitMessage",
	"NtUserWin32PoolAllocationStats",
	"NtUserWindowFromPoint",
	"NtUserYieldTask",
	"NtUserRemoteConnect",
	"NtUserRemoteRedrawRectangle",
	"NtUserRemoteRedrawScreen",
	"NtUserRemoteStopScreenUpdates",
	"NtUserCtxDisplayIOCtl",
	"NtGdiEngAssociateSurface",
	"NtGdiEngCreateBitmap",
	"NtGdiEngCreateDeviceSurface",
	"NtGdiEngCreateDeviceBitmap",
	"NtGdiEngCreatePalette",
	"NtGdiEngComputeGlyphSet",
	"NtGdiEngCopyBits",
	"NtGdiEngDeletePalette",
	"NtGdiEngDeleteSurface",
	"NtGdiEngEraseSurface",
	"NtGdiEngUnlockSurface",
	"NtGdiEngLockSurface",
	"NtGdiEngBitBlt",
	"NtGdiEngStretchBlt",
	"NtGdiEngPlgBlt",
	"NtGdiEngMarkBandingSurface",
	"NtGdiEngStrokePath",
	"NtGdiEngFillPath",
	"NtGdiEngStrokeAndFillPath",
	"NtGdiEngPaint",
	"NtGdiEngLineTo",
	"NtGdiEngAlphaBlend",
	"NtGdiEngGradientFill",
	"NtGdiEngTransparentBlt",
	"NtGdiEngTextOut",
	"NtGdiEngStretchBltROP",
	"NtGdiXLATEOBJ_cGetPalette",
	"NtGdiXLATEOBJ_iXlate",
	"NtGdiXLATEOBJ_hGetColorTransform",
	"NtGdiCLIPOBJ_bEnum",
	"NtGdiCLIPOBJ_cEnumStart",
	"NtGdiCLIPOBJ_ppoGetPath",
	"NtGdiEngDeletePath",
	"NtGdiEngCreateClip",
	"NtGdiEngDeleteClip",
	"NtGdiBRUSHOBJ_ulGetBrushColor",
	"NtGdiBRUSHOBJ_pvAllocRbrush",
	"NtGdiBRUSHOBJ_pvGetRbrush",
	"NtGdiBRUSHOBJ_hGetColorTransform",
	"NtGdiXFORMOBJ_bApplyXform",
	"NtGdiXFORMOBJ_iGetXform",
	"NtGdiFONTOBJ_vGetInfo",
	"NtGdiFONTOBJ_pxoGetXform",
	"NtGdiFONTOBJ_cGetGlyphs",
	"NtGdiFONTOBJ_pifi",
	"NtGdiFONTOBJ_pfdg",
	"NtGdiFONTOBJ_pQueryGlyphAttrs",
	"NtGdiFONTOBJ_pvTrueTypeFontFile",
	"NtGdiFONTOBJ_cGetAllGlyphHandles",
	"NtGdiSTROBJ_bEnum",
	"NtGdiSTROBJ_bEnumPositionsOnly",
	"NtGdiSTROBJ_bGetAdvanceWidths",
	"NtGdiSTROBJ_vEnumStart",
	"NtGdiSTROBJ_dwGetCodePage",
	"NtGdiPATHOBJ_vGetBounds",
	"NtGdiPATHOBJ_bEnum",
	"NtGdiPATHOBJ_vEnumStart",
	"NtGdiPATHOBJ_vEnumStartClipLines",
	"NtGdiPATHOBJ_bEnumClipLines",
	"NtGdiGetDhpdev",
	"NtGdiEngCheckAbort",
	"NtGdiHT_Get8BPPFormatPalette",
	"NtGdiHT_Get8BPPMaskPalette",
	"NtGdiUpdateTransform",
	"NtGdiSetPUMPDOBJ",
	"NtGdiBRUSHOBJ_DeleteRbrush",
	"NtGdiUMPDEngFreeUserMem",
	"NtGdiDrawStream",
	"NtUserDbgWin32HeapFail",
	"NtUserDbgWin32HeapStat",
	"NtUserSetDbgTag",
	"NtUserSetDbgTagCount",
	"NtUserSetRipFlags",
	"NtGdiMakeObjectXferable",
	"NtDxEngGetRedirectionBitmap",
	"NtGdiSetViewportOrgEx",
	"NtGdiSetWindowOrgEx",
	"NtGdiGetFontFamilyInfo",
	"NtGdiOffsetViewportOrgEx",
	"NtGdiOffsetWindowOrgEx",
	"NtUserGetMonitorInfo",
	"NtUserMonitorFromPoint",
	"NtUserMonitorFromRect",
	"NtUserMonitorFromWindow",
	"NtUserSetScrollBarInfo",
	"NtGdiDdDDICreateDCFromMemory",
	"NtGdiDdDDIDestroyDCFromMemory",
	"NtGdiDdDDICheckExclusiveOwnership",
	"NtGdiDdDDICreateAllocation",
	"NtGdiDdDDICheckMonitorPowerState",
	"NtGdiDdDDICheckOcclusion",
	"NtGdiDdDDICloseAdapter",
	"NtGdiDdDDICreateContext",
	"NtGdiDdDDICreateDevice",
	"NtGdiDdDDICreateOverlay",
	"NtGdiDdDDICreateSynchronizationObject",
	"NtGdiDdDDIWaitForVerticalBlankEvent",
	"NtGdiDdDDIWaitForIdle",
	"NtGdiDdDDIUpdateOverlay",
	"NtGdiDdDDIUnlock",
	"NtGdiDdDDIDestroyAllocation",
	"NtGdiDdDDIDestroyContext",
	"NtGdiDdDDIDestroyDevice",
	"NtGdiDdDDIDestroyOverlay",
	"NtGdiDdDDIDestroySynchronizationObject",
	"NtGdiDdDDIEscape",
	"NtGdiDdDDIFlipOverlay",
	"NtGdiDdDDIGetContextSchedulingPriority",
	"NtGdiDdDDIGetDeviceState",
	"NtGdiDdDDIGetDisplayModeList",
	"NtGdiDdDDIGetMultisampleMethodList",
	"NtGdiDdDDIGetPresentHistory",
	"NtGdiDdDDIGetProcessSchedulingPriorityClass",
	"NtGdiDdDDIGetRuntimeData",
	"NtGdiDdDDIGetScanLine",
	"NtGdiDdDDIGetSharedPrimaryHandle",
	"NtGdiDdDDIInvalidateActiveVidPn",
	"NtGdiDdDDILock",
	"NtGdiDdDDIOpenAdapterFromDeviceName",
	"NtGdiDdDDIOpenAdapterFromGdiDisplayName",
	"NtGdiDdDDIOpenAdapterFromHdc",
	"NtGdiDdDDIOpenResource",
	"NtGdiDdDDIPollDisplayChildren",
	"NtGdiDdDDIPresent",
	"NtGdiDdDDIQueryAdapterInfo",
	"NtGdiDdDDIQueryAllocationResidency",
	"NtGdiDdDDIQueryResourceInfo",
	"NtGdiDdDDIQueryStatistics",
	"NtGdiDdDDIReleaseProcessVidPnSourceOwners",
	"NtGdiDdDDIRender",
	"NtGdiDdDDISetAllocationPriority",
	"NtGdiDdDDISetContextSchedulingPriority",
	"NtGdiDdDDISetDisplayMode",
	"NtGdiDdDDISetDisplayPrivateDriverFormat",
	"NtGdiDdDDISetGammaRamp",
	"NtGdiDdDDISetProcessSchedulingPriorityClass",
	"NtGdiDdDDISetQueuedLimit",
	"NtGdiDdDDISetVidPnSourceOwner",
	"NtGdiDdDDISharedPrimaryLockNotification",
	"NtGdiDdDDISharedPrimaryUnLockNotification",
	"NtGdiDdDDISignalSynchronizationObject",
	"NtGdiDdDDIWaitForSynchronizationObject",
	// --- Raven extras (not in the ReactOS SSDT; ids past the real table) ---
	"NtGdiDdDDIOpenAdapterFromLuid",
	"NtGdiEnumFonts",
	"NtGdiGetFontFileData",
	"NtGdiGetFontFileInfo",
	"NtUserAddClipboardFormatListener",
	"NtUserCreateDesktopEx",
	"NtUserDeferWindowPosAndBand",
	"NtUserDefWindowProc",
	"NtUserDisplayConfigGetDeviceInfo",
	"NtUserEnableMouseInPointer",
	"NtUserGetClassInfoEx",
	"NtUserGetCursor",
	"NtUserGetCursorPos",
	"NtUserGetDisplayConfigBufferSizes",
	"NtUserGetDpiForMonitor",
	"NtUserGetKeyboardLayout",
	"NtUserGetProcessDpiAwarenessContext",
	"NtUserGetProp",
	"NtUserGetQueueStatus",
	"NtUserGetSystemDpiForProcess",
	"NtUserGetTouchInputInfo",
	"NtUserGetUpdatedClipboardFormats",
	"NtUserGetWindowRgnEx",
	"NtUserInternalGetWindowIcon",
	"NtUserIsMouseInPointerEnabled",
	"NtUserIsTouchWindow",
	"NtUserLogicalToPerMonitorDPIPhysicalPoint",
	"NtUserMsgWaitForMultipleObjectsEx",
	"NtUserPerMonitorDPIPhysicalToLogicalPoint",
	"NtUserQueryDisplayConfig",
	"NtUserReleaseDC",
	"NtUserReleaseCapture",
	"NtUserRemoveClipboardFormatListener",
	"NtUserSendMessage",
	"NtUserSetClassLongPtr",
	"NtUserSetCursorPos",
	"NtUserSetProcessDpiAwarenessContext",
	"NtUserShowCursor",
	"NtUserSystemParametersInfoForDpi",
	"NtUserUpdateWindow",
	"NtUserWindowFromDC",
	"__wine_get_file_outline_text_metric",
	"__wine_get_icm_profile",
	"NtGdiFillRect",
	"NtGdiSelectObject",
	"NtGdiSetBkColor",
	"NtGdiSetBkMode",
	"NtGdiSetTextColor",
	"NtGdiTextOutW",
	"NtGdiGetTextExtentPoint32W",
	"NtGdiPolyline",
	"NtGdiCreateFontIndirectW",
	"NtUserGetClientRect",
	"NtUserGetWindowRect",
	"NtUserRegisterClassEx",
}

const (
	// Syscall ID ranges
	ntapiIDBase     = 0x0000 // NtXxx/RtlXxx syscalls: 0x0000-0x0FFF
	win32uIDBase    = 0x1000 // NtUser*/NtGdi* syscalls: 0x1000-0x1FFF
	AutoSynthIDBase = 0x2000 // auto-generated stub DLLs: 0x2000-0xFFDD

	// DynExportIDBase is the starting ID for dynamically added exports
	// (functions registered at runtime via RegisterDynamicHandler).
	DynExportIDBase = 0xE000 // dynamic exports: 0xE000-0xFFDD

	// DllMainReturnID is a sentinel syscall ID used by the DllMain return
	// trampoline. When the CPU hits this, the dispatcher stops execution.
	DllMainReturnID = 0xFFDE

	// CatchReturnID is used by the C++ catch funclet return trampoline.
	// When a catch funclet RETs, execution hits this vmcall; the handler
	// checks RAX and either jumps to the continuation or handles re-throw.
	CatchReturnID = 0xFFDF
)

// stubSize is the padded size of each trap stub.
// We use 32 bytes to allow fast inline replacements for hot functions.
const stubSize = 64

// GenerateSynthDLL creates a minimal PE image in guest memory with trap stubs.
func GenerateSynthDLL(mem *mmu.MMU, name string, exports []string, idBase uint32) *SynthPE {
	synth := &SynthPE{
		Name:       name,
		Exports:    make(map[string]uint64),
		StubIDs:    make(map[uint64]uint32),
		ExportOrds: make(map[uint16]uint64),
	}

	numExports := uint32(len(exports))
	exportOrdinals := make([]uint16, len(exports))
	usedOrdinals := make(map[uint16]bool, len(exports))
	for i, exportName := range exports {
		if ordinal, ok := knownSynthOrdinals[strings.ToLower(name)][exportName]; ok {
			exportOrdinals[i] = ordinal
			usedOrdinals[ordinal] = true
		}
	}
	var nextOrdinal uint16
	for i, exportName := range exports {
		if _, ok := knownSynthOrdinals[strings.ToLower(name)][exportName]; ok {
			continue
		}
		for usedOrdinals[nextOrdinal] {
			nextOrdinal++
		}
		exportOrdinals[i] = nextOrdinal
		usedOrdinals[nextOrdinal] = true
		nextOrdinal++
	}
	numOrdinalSlots := uint32(0)
	for _, ordinal := range exportOrdinals {
		if slots := uint32(ordinal) + 1; slots > numOrdinalSlots {
			numOrdinalSlots = slots
		}
	}

	// Calculate sizes
	// PE headers: ~512 bytes
	// .text section: stubs
	// .edata section: export directory + name pointers + ordinals + name strings
	headerSize := uint64(512)
	textSize := uint64(numExports) * stubSize
	textRVA := uint64(0x1000) // section-aligned

	// Export directory structures
	nameDataSize := uint64(0)
	for _, n := range exports {
		nameDataSize += uint64(len(n)) + 1
	}
	nameDataSize += uint64(len(name)) + 1
	edataSize := 40 + // IMAGE_EXPORT_DIRECTORY
		numOrdinalSlots*4 + // AddressOfFunctions (RVAs)
		numExports*4 + // AddressOfNames (RVAs)
		numExports*2 + // AddressOfNameOrdinals
		uint32(nameDataSize)
	edataRVA := (textRVA + textSize + 0xFFF) & ^uint64(0xFFF) // section-aligned

	sizeOfImage := (edataRVA + uint64(edataSize) + 0xFFF) & ^uint64(0xFFF)

	// Allocate guest memory
	baseAddr := mem.Mmap(0, sizeOfImage, mmu.PermRead|mmu.PermWrite|mmu.PermExecute)
	synth.BaseAddr = baseAddr
	synth.ImageSize = sizeOfImage

	// --- Write minimal PE headers ---
	// DOS header
	mem.Write16(baseAddr, 0x5A4D)    // "MZ"
	mem.Write32(baseAddr+0x3C, 0x80) // e_lfanew

	// PE signature
	mem.Write32(baseAddr+0x80, 0x00004550) // "PE\0\0"

	// COFF header (20 bytes at offset 0x84)
	coff := baseAddr + 0x84
	mem.Write16(coff+0, 0x8664)  // Machine = AMD64
	mem.Write16(coff+2, 2)       // NumberOfSections (.text, .edata)
	mem.Write16(coff+16, 0xF0)   // SizeOfOptionalHeader
	mem.Write16(coff+18, 0x2022) // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL

	// Optional header (PE32+ at offset 0x98)
	opt := baseAddr + 0x98
	mem.Write16(opt+0, 0x020B)               // Magic = PE32+
	mem.Write32(opt+16, uint32(textRVA))     // AddressOfEntryPoint (dummy)
	mem.Write64(opt+24, baseAddr)            // ImageBase
	mem.Write32(opt+32, 0x1000)              // SectionAlignment
	mem.Write32(opt+36, 0x200)               // FileAlignment
	mem.Write16(opt+40, 6)                   // MajorOperatingSystemVersion
	mem.Write16(opt+42, 0)                   // MinorOperatingSystemVersion
	mem.Write16(opt+48, 6)                   // MajorSubsystemVersion
	mem.Write32(opt+56, uint32(sizeOfImage)) // SizeOfImage
	mem.Write32(opt+60, uint32(headerSize))  // SizeOfHeaders
	mem.Write16(opt+68, 3)                   // Subsystem = WINDOWS_CUI
	mem.Write16(opt+70, 0x0160)              // DllCharacteristics (DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA)
	mem.Write32(opt+108, 16)                 // NumberOfRvaAndSizes

	// Export directory entry in DataDirectory[0]
	dataDirBase := opt + 112
	mem.Write32(dataDirBase+0, uint32(edataRVA))
	mem.Write32(dataDirBase+4, edataSize)

	// Section headers (at offset 0x188)
	secBase := baseAddr + 0x188

	// .text section
	writeSectionName(mem, secBase, ".text")
	mem.Write32(secBase+8, uint32(textSize))  // VirtualSize
	mem.Write32(secBase+12, uint32(textRVA))  // VirtualAddress
	mem.Write32(secBase+16, uint32(textSize)) // SizeOfRawData
	mem.Write32(secBase+20, uint32(textRVA))  // PointerToRawData
	mem.Write32(secBase+36, imageScnMemExecute|imageScnMemRead|imageScnCntCode)

	// .edata section
	secBase2 := secBase + 40
	writeSectionName(mem, secBase2, ".edata")
	mem.Write32(secBase2+8, edataSize)         // VirtualSize
	mem.Write32(secBase2+12, uint32(edataRVA)) // VirtualAddress
	mem.Write32(secBase2+16, edataSize)        // SizeOfRawData
	mem.Write32(secBase2+20, uint32(edataRVA)) // PointerToRawData
	mem.Write32(secBase2+36, imageScnMemRead)

	// --- Write .text section: trap stubs ---
	for i, exportName := range exports {
		stubAddr := baseAddr + textRVA + uint64(i)*stubSize
		syscallID := idBase + uint32(i)

		// mov eax, <syscall_id>  (B8 xx xx xx xx)
		mem.Write8(stubAddr+0, 0xB8)
		mem.Write32(stubAddr+1, syscallID)
		// vmcall                  (0F 01 C1)
		mem.WriteBytes(stubAddr+5, vmTrapBytes)
		// ret                     (C3)
		mem.Write8(stubAddr+8, 0xC3)

		synth.Exports[exportName] = stubAddr
		synth.StubIDs[stubAddr] = syscallID
		synth.ExportOrds[exportOrdinals[i]] = stubAddr
	}

	// --- Write .edata section: export directory ---
	exportDir := baseAddr + edataRVA
	funcTableRVA := edataRVA + 40
	nameTableRVA := funcTableRVA + uint64(numOrdinalSlots)*4
	ordTableRVA := nameTableRVA + uint64(numExports)*4
	nameStringsRVA := ordTableRVA + uint64(numExports)*2

	// IMAGE_EXPORT_DIRECTORY
	mem.Write32(exportDir+12, uint32(nameStringsRVA)) // Name RVA
	mem.Write32(exportDir+16, 0)                      // OrdinalBase
	mem.Write32(exportDir+20, numOrdinalSlots)        // NumberOfFunctions
	mem.Write32(exportDir+24, numExports)             // NumberOfNames
	mem.Write32(exportDir+28, uint32(funcTableRVA))
	mem.Write32(exportDir+32, uint32(nameTableRVA))
	mem.Write32(exportDir+36, uint32(ordTableRVA))

	// Write DLL name at a known location
	dllNameRVA := nameStringsRVA
	mem.WriteBytes(baseAddr+dllNameRVA, append([]byte(name), 0))
	mem.Write32(exportDir+12, uint32(dllNameRVA))

	// Function RVAs, name RVAs, ordinals, and name strings
	nameStrCursor := nameStringsRVA + uint64(len(name)) + 1
	for i, exportName := range exports {
		// Function RVA
		funcRVA := textRVA + uint64(i)*stubSize
		mem.Write32(baseAddr+funcTableRVA+uint64(exportOrdinals[i])*4, uint32(funcRVA))

		// Name RVA
		mem.Write32(baseAddr+nameTableRVA+uint64(i)*4, uint32(nameStrCursor))

		// Name ordinal indexes the sparse function table.
		mem.Write16(baseAddr+ordTableRVA+uint64(i)*2, exportOrdinals[i])

		// Name string
		mem.WriteBytes(baseAddr+nameStrCursor, append([]byte(exportName), 0))
		nameStrCursor += uint64(len(exportName)) + 1
	}

	return synth
}

// GenerateNtdll creates the synthetic ntdll.dll.
func GenerateNtdll(mem *mmu.MMU) *SynthPE {
	return GenerateSynthDLL(mem, "ntdll.dll", ntapiExports, ntapiIDBase)
}

// GenerateWin32u creates the synthetic win32u.dll.
func GenerateWin32u(mem *mmu.MMU) *SynthPE {
	return GenerateSynthDLL(mem, "win32u.dll", win32uExports, win32uIDBase)
}

// SynthToModule converts a SynthPE to a PEModule for import resolution.
func SynthToModule(s *SynthPE) *loader.PEModule {
	return &loader.PEModule{
		Name:       s.Name,
		Path:       fmt.Sprintf("<synthetic:%s>", s.Name),
		BaseAddr:   s.BaseAddr,
		ImageSize:  s.ImageSize,
		EntryPoint: s.BaseAddr, // not used
		Exports:    s.Exports,
		ExportOrds: s.ExportOrds,
		Forwards:   make(map[string]string),
		Is64:       true,
	}
}

func writeSectionName(mem *mmu.MMU, addr uint64, name string) {
	b := []byte(name)
	if len(b) > 8 {
		b = b[:8]
	}
	padded := make([]byte, 8)
	copy(padded, b)
	mem.WriteBytes(addr, padded)
}

// write32LE is a helper to encode uint32 into a byte slice.
func write32LE(buf []byte, offset int, val uint32) {
	binary.LittleEndian.PutUint32(buf[offset:], val)
}

package ntapi

import (
	"encoding/binary"
	"fmt"

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
	Exports    map[string]uint64  // name → guest address of stub
	StubIDs    map[uint64]uint32  // guest address → syscall ID
	ExportOrds map[uint16]uint64  // export ordinal → guest address of stub
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
	"NtAllocateLocallyUniqueId",
	"NtAllocateVirtualMemory",
	"NtAllocateVirtualMemoryEx",
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
	"NtQueryObject",
	"NtQueryPerformanceCounter",
	"NtQuerySection",
	"NtQuerySecurityObject",
	"NtQuerySymbolicLinkObject",
	"NtQuerySystemInformation",
	"NtQuerySystemInformationEx",
	"NtQuerySystemTime",
	"NtQueryTimer",
	"NtQueryValueKey",
	"NtQueryVirtualMemory",
	"NtQueryVolumeInformationFile",
	"NtQueueApcThread",
	"NtReadFile",
	"NtReadFileScatter",
	"NtReadVirtualMemory",
	"NtReleaseMutant",
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
	"NtSetValueKey",
	"NtSignalAndWaitForSingleObject",
	"NtSuspendThread",
	"NtTerminateJobObject",
	"NtTerminateProcess",
	"NtTerminateThread",
	"NtUnloadKey",
	"NtUnlockFile",
	"NtUnlockVirtualMemory",
	"NtUnmapViewOfSection",
	"NtUnmapViewOfSectionEx",
	"NtWaitForMultipleObjects",
	"NtWaitForSingleObject",
	"NtWriteFile",
	"NtWriteFileGather",
	"NtWriteVirtualMemory",
	"NtYieldExecution",

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
	"RtlDeleteAce",
	"RtlDeleteAtomFromAtomTable",
	"RtlDeleteCriticalSection",
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
}

// win32uExports lists Win32k syscall stubs for win32u.dll.
var win32uExports = []string{
	// NtGdi* - Graphics Device Interface (161 functions)
	"NtGdiAbortDoc",
	"NtGdiAbortPath",
	"NtGdiAddFontMemResourceEx",
	"NtGdiAddFontResourceW",
	"NtGdiAlphaBlend",
	"NtGdiAngleArc",
	"NtGdiArcInternal",
	"NtGdiBeginPath",
	"NtGdiBitBlt",
	"NtGdiCloseFigure",
	"NtGdiCombineRgn",
	"NtGdiComputeXformCoefficients",
	"NtGdiCreateBitmap",
	"NtGdiCreateClientObj",
	"NtGdiCreateCompatibleBitmap",
	"NtGdiCreateCompatibleDC",
	"NtGdiCreateDIBBrush",
	"NtGdiCreateDIBSection",
	"NtGdiCreateDIBitmapInternal",
	"NtGdiCreateEllipticRgn",
	"NtGdiCreateHalftonePalette",
	"NtGdiCreateHatchBrushInternal",
	"NtGdiCreateMetafileDC",
	"NtGdiCreatePaletteInternal",
	"NtGdiCreatePatternBrushInternal",
	"NtGdiCreatePen",
	"NtGdiCreateRectRgn",
	"NtGdiCreateRoundRectRgn",
	"NtGdiCreateSolidBrush",
	"NtGdiDdDDIOpenAdapterFromLuid",
	"NtGdiDeleteClientObj",
	"NtGdiDeleteObjectApp",
	"NtGdiDescribePixelFormat",
	"NtGdiDoPalette",
	"NtGdiDrawStream",
	"NtGdiEllipse",
	"NtGdiEndDoc",
	"NtGdiEndPage",
	"NtGdiEndPath",
	"NtGdiEnumFonts",
	"NtGdiEqualRgn",
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
	"NtGdiFontIsLinked",
	"NtGdiFrameRgn",
	"NtGdiGetAndSetDCDword",
	"NtGdiGetAppClipBox",
	"NtGdiGetBitmapBits",
	"NtGdiGetBitmapDimension",
	"NtGdiGetBoundsRect",
	"NtGdiGetCharABCWidthsW",
	"NtGdiGetCharWidthInfo",
	"NtGdiGetCharWidthW",
	"NtGdiGetColorAdjustment",
	"NtGdiGetDCObject",
	"NtGdiGetDIBitsInternal",
	"NtGdiGetDeviceCaps",
	"NtGdiGetDeviceGammaRamp",
	"NtGdiGetFontData",
	"NtGdiGetFontFileData",
	"NtGdiGetFontFileInfo",
	"NtGdiGetFontUnicodeRanges",
	"NtGdiGetGlyphIndicesW",
	"NtGdiGetGlyphOutline",
	"NtGdiGetKerningPairs",
	"NtGdiGetNearestColor",
	"NtGdiGetNearestPaletteIndex",
	"NtGdiGetOutlineTextMetricsInternalW",
	"NtGdiGetPath",
	"NtGdiGetPixel",
	"NtGdiGetRandomRgn",
	"NtGdiGetRasterizerCaps",
	"NtGdiGetRealizationInfo",
	"NtGdiGetRegionData",
	"NtGdiGetRgnBox",
	"NtGdiGetSpoolMessage",
	"NtGdiGetSystemPaletteUse",
	"NtGdiGetTextCharsetInfo",
	"NtGdiGetTextExtentExW",
	"NtGdiGetTextFaceW",
	"NtGdiGetTextMetricsW",
	"NtGdiGetTransform",
	"NtGdiGradientFill",
	"NtGdiHfontCreate",
	"NtGdiIcmBrushInfo",
	"NtGdiInitSpool",
	"NtGdiIntersectClipRect",
	"NtGdiInvertRgn",
	"NtGdiLineTo",
	"NtGdiMaskBlt",
	"NtGdiModifyWorldTransform",
	"NtGdiMoveTo",
	"NtGdiOffsetClipRgn",
	"NtGdiOffsetRgn",
	"NtGdiOpenDCW",
	"NtGdiPatBlt",
	"NtGdiPathToRegion",
	"NtGdiPlgBlt",
	"NtGdiPolyDraw",
	"NtGdiPolyPolyDraw",
	"NtGdiPtInRegion",
	"NtGdiPtVisible",
	"NtGdiRectInRegion",
	"NtGdiRectVisible",
	"NtGdiRectangle",
	"NtGdiRemoveFontMemResourceEx",
	"NtGdiRemoveFontResourceW",
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
	"NtGdiSetBitmapBits",
	"NtGdiSetBitmapDimension",
	"NtGdiSetBoundsRect",
	"NtGdiSetColorAdjustment",
	"NtGdiSetDIBitsToDeviceInternal",
	"NtGdiSetDeviceGammaRamp",
	"NtGdiSetLayout",
	"NtGdiSetMagicColors",
	"NtGdiSetMetaRgn",
	"NtGdiSetPixel",
	"NtGdiSetPixelFormat",
	"NtGdiSetRectRgn",
	"NtGdiSetSystemPaletteUse",
	"NtGdiSetTextJustification",
	"NtGdiSetVirtualResolution",
	"NtGdiStartDoc",
	"NtGdiStartPage",
	"NtGdiStretchBlt",
	"NtGdiStretchDIBitsInternal",
	"NtGdiStrokeAndFillPath",
	"NtGdiStrokePath",
	"NtGdiSwapBuffers",
	"NtGdiTransformPoints",
	"NtGdiTransparentBlt",
	"NtGdiUnrealizeObject",
	"NtGdiUpdateColors",
	"NtGdiWidenPath",

	// NtUser* - User Interface (215 functions from user32 + 10 from imm32)
	"NtUserActivateKeyboardLayout",
	"NtUserAddClipboardFormatListener",
	"NtUserAssociateInputContext",
	"NtUserAttachThreadInput",
	"NtUserBeginPaint",
	"NtUserBuildHimcList",
	"NtUserCallHwnd",
	"NtUserCallHwndParam",
	"NtUserCallMsgFilter",
	"NtUserCallNextHookEx",
	"NtUserCallNoParam",
	"NtUserCallOneParam",
	"NtUserCallTwoParam",
	"NtUserChangeClipboardChain",
	"NtUserChangeDisplaySettings",
	"NtUserCheckMenuItem",
	"NtUserChildWindowFromPointEx",
	"NtUserClipCursor",
	"NtUserCloseClipboard",
	"NtUserCloseDesktop",
	"NtUserCloseWindowStation",
	"NtUserCopyAcceleratorTable",
	"NtUserCountClipboardFormats",
	"NtUserCreateAcceleratorTable",
	"NtUserCreateCaret",
	"NtUserCreateDesktopEx",
	"NtUserCreateInputContext",
	"NtUserCreateWindowEx",
	"NtUserCreateWindowStation",
	"NtUserDeferWindowPosAndBand",
	"NtUserDefWindowProc",
	"NtUserDeleteMenu",
	"NtUserDestroyAcceleratorTable",
	"NtUserDestroyCursor",
	"NtUserDestroyInputContext",
	"NtUserDestroyMenu",
	"NtUserDestroyWindow",
	"NtUserDisableThreadIme",
	"NtUserDispatchMessage",
	"NtUserDisplayConfigGetDeviceInfo",
	"NtUserDragDetect",
	"NtUserDragObject",
	"NtUserDrawCaptionTemp",
	"NtUserDrawIconEx",
	"NtUserDrawMenuBarTemp",
	"NtUserEmptyClipboard",
	"NtUserEnableMenuItem",
	"NtUserEnableMouseInPointer",
	"NtUserEnableScrollBar",
	"NtUserEndDeferWindowPosEx",
	"NtUserEndMenu",
	"NtUserEndPaint",
	"NtUserEnumDisplayDevices",
	"NtUserEnumDisplayMonitors",
	"NtUserEnumDisplaySettings",
	"NtUserExcludeUpdateRgn",
	"NtUserFindExistingCursorIcon",
	"NtUserFindWindowEx",
	"NtUserFlashWindowEx",
	"NtUserGetAncestor",
	"NtUserGetAsyncKeyState",
	"NtUserGetCaretBlinkTime",
	"NtUserGetCaretPos",
	"NtUserGetClassInfoEx",
	"NtUserGetClassName",
	"NtUserGetClipboardData",
	"NtUserGetClipboardFormatName",
	"NtUserGetClipboardOwner",
	"NtUserGetClipboardSequenceNumber",
	"NtUserGetClipboardViewer",
	"NtUserGetCursor",
	"NtUserGetCursorFrameInfo",
	"NtUserGetCursorInfo",
	"NtUserGetCursorPos",
	"NtUserGetDC",
	"NtUserGetDCEx",
	"NtUserGetDisplayConfigBufferSizes",
	"NtUserGetDoubleClickTime",
	"NtUserGetDpiForMonitor",
	"NtUserGetForegroundWindow",
	"NtUserGetGUIThreadInfo",
	"NtUserGetIconInfo",
	"NtUserGetIconSize",
	"NtUserGetInternalWindowPos",
	"NtUserGetKeyNameText",
	"NtUserGetKeyState",
	"NtUserGetKeyboardLayout",
	"NtUserGetKeyboardLayoutList",
	"NtUserGetKeyboardLayoutName",
	"NtUserGetKeyboardState",
	"NtUserGetLayeredWindowAttributes",
	"NtUserGetMenuBarInfo",
	"NtUserGetMenuItemRect",
	"NtUserGetMessage",
	"NtUserGetMouseMovePointsEx",
	"NtUserGetObjectInformation",
	"NtUserGetOpenClipboardWindow",
	"NtUserGetPriorityClipboardFormat",
	"NtUserGetProcessDpiAwarenessContext",
	"NtUserGetProcessWindowStation",
	"NtUserGetProp",
	"NtUserGetQueueStatus",
	"NtUserGetRawInputBuffer",
	"NtUserGetRawInputData",
	"NtUserGetRawInputDeviceInfo",
	"NtUserGetRawInputDeviceList",
	"NtUserGetRegisteredRawInputDevices",
	"NtUserGetScrollBarInfo",
	"NtUserGetSystemDpiForProcess",
	"NtUserGetSystemMenu",
	"NtUserGetThreadDesktop",
	"NtUserGetTitleBarInfo",
	"NtUserGetTouchInputInfo",
	"NtUserGetUpdateRect",
	"NtUserGetUpdateRgn",
	"NtUserGetUpdatedClipboardFormats",
	"NtUserGetWindowDC",
	"NtUserGetWindowPlacement",
	"NtUserGetWindowRgnEx",
	"NtUserHideCaret",
	"NtUserHiliteMenuItem",
	"NtUserInitializeClientPfnArrays",
	"NtUserInternalGetWindowIcon",
	"NtUserInternalGetWindowText",
	"NtUserInvalidateRect",
	"NtUserInvalidateRgn",
	"NtUserIsClipboardFormatAvailable",
	"NtUserIsMouseInPointerEnabled",
	"NtUserIsTouchWindow",
	"NtUserKillTimer",
	"NtUserLockWindowUpdate",
	"NtUserLogicalToPerMonitorDPIPhysicalPoint",
	"NtUserMapVirtualKeyEx",
	"NtUserMenuItemFromPoint",
	"NtUserMessageCall",
	"NtUserMoveWindow",
	"NtUserMsgWaitForMultipleObjectsEx",
	"NtUserNotifyIMEStatus",
	"NtUserNotifyWinEvent",
	"NtUserOpenClipboard",
	"NtUserOpenDesktop",
	"NtUserOpenInputDesktop",
	"NtUserOpenWindowStation",
	"NtUserPeekMessage",
	"NtUserPerMonitorDPIPhysicalToLogicalPoint",
	"NtUserPostMessage",
	"NtUserPostThreadMessage",
	"NtUserPrintWindow",
	"NtUserQueryDisplayConfig",
	"NtUserQueryInputContext",
	"NtUserRealChildWindowFromPoint",
	"NtUserRedrawWindow",
	"NtUserRegisterClassExWOW",
	"NtUserRegisterHotKey",
	"NtUserRegisterRawInputDevices",
	"NtUserReleaseDC",
	"NtUserReleaseCapture",
	"NtUserRemoveClipboardFormatListener",
	"NtUserRemoveMenu",
	"NtUserRemoveProp",
	"NtUserScrollDC",
	"NtUserScrollWindowEx",
	"NtUserSelectPalette",
	"NtUserSendInput",
	"NtUserSendMessage",
	"NtUserSetActiveWindow",
	"NtUserSetCapture",
	"NtUserSetClassLong",
	"NtUserSetClassLongPtr",
	"NtUserSetClassWord",
	"NtUserSetClipboardData",
	"NtUserSetClipboardViewer",
	"NtUserSetCursor",
	"NtUserSetCursorIconData",
	"NtUserSetCursorPos",
	"NtUserSetFocus",
	"NtUserSetInternalWindowPos",
	"NtUserSetKeyboardState",
	"NtUserSetLayeredWindowAttributes",
	"NtUserSetMenu",
	"NtUserSetMenuContextHelpId",
	"NtUserSetMenuDefaultItem",
	"NtUserSetObjectInformation",
	"NtUserSetParent",
	"NtUserSetProcessDpiAwarenessContext",
	"NtUserSetProcessWindowStation",
	"NtUserSetProp",
	"NtUserSetScrollInfo",
	"NtUserSetShellWindowEx",
	"NtUserSetSysColors",
	"NtUserSetSystemMenu",
	"NtUserSetSystemTimer",
	"NtUserSetThreadDesktop",
	"NtUserSetTimer",
	"NtUserSetWinEventHook",
	"NtUserSetWindowLong",
	"NtUserSetWindowLongPtr",
	"NtUserSetWindowPlacement",
	"NtUserSetWindowPos",
	"NtUserSetWindowRgn",
	"NtUserSetWindowWord",
	"NtUserSetWindowsHookEx",
	"NtUserShowCaret",
	"NtUserShowCursor",
	"NtUserShowScrollBar",
	"NtUserShowWindow",
	"NtUserShowWindowAsync",
	"NtUserSystemParametersInfo",
	"NtUserSystemParametersInfoForDpi",
	"NtUserThunkedMenuInfo",
	"NtUserThunkedMenuItemInfo",
	"NtUserToUnicodeEx",
	"NtUserTrackMouseEvent",
	"NtUserTrackPopupMenuEx",
	"NtUserTranslateAccelerator",
	"NtUserTranslateMessage",
	"NtUserUnhookWinEvent",
	"NtUserUnhookWindowsHookEx",
	"NtUserUnregisterClass",
	"NtUserUnregisterHotKey",
	"NtUserUpdateInputContext",
	"NtUserUpdateLayeredWindow",
	"NtUserUpdateWindow",
	"NtUserValidateRect",
	"NtUserVkKeyScanEx",
	"NtUserWaitForInputIdle",
	"NtUserWaitMessage",
	"NtUserWindowFromDC",
	"NtUserWindowFromPoint",

	// Wine internal extensions
	"__wine_get_file_outline_text_metric",
	"__wine_get_icm_profile",

	// Legacy names used by pkg/win32k handlers (backward compat)
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
	ntapiIDBase  = 0x0000 // NtXxx/RtlXxx syscalls: 0x0000-0x0FFF
	win32uIDBase = 0x1000 // NtUser*/NtGdi* syscalls: 0x1000-0x1FFF
	AutoSynthIDBase = 0x2000 // auto-generated stub DLLs: 0x2000-0xFFDD

	// DllMainReturnID is a sentinel syscall ID used by the DllMain return
	// trampoline. When the CPU hits this, the dispatcher stops execution.
	DllMainReturnID = 0xFFDE
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
	edataSize := 40 + // IMAGE_EXPORT_DIRECTORY
		numExports*4 + // AddressOfFunctions (RVAs)
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
	mem.Write16(baseAddr, 0x5A4D) // "MZ"
	mem.Write32(baseAddr+0x3C, 0x80) // e_lfanew

	// PE signature
	mem.Write32(baseAddr+0x80, 0x00004550) // "PE\0\0"

	// COFF header (20 bytes at offset 0x84)
	coff := baseAddr + 0x84
	mem.Write16(coff+0, 0x8664) // Machine = AMD64
	mem.Write16(coff+2, 2)      // NumberOfSections (.text, .edata)
	mem.Write16(coff+16, 0xF0)  // SizeOfOptionalHeader
	mem.Write16(coff+18, 0x2022) // Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE | DLL

	// Optional header (PE32+ at offset 0x98)
	opt := baseAddr + 0x98
	mem.Write16(opt+0, 0x020B)           // Magic = PE32+
	mem.Write32(opt+16, uint32(textRVA)) // AddressOfEntryPoint (dummy)
	mem.Write64(opt+24, baseAddr)        // ImageBase
	mem.Write32(opt+32, 0x1000)          // SectionAlignment
	mem.Write32(opt+36, 0x200)           // FileAlignment
	mem.Write16(opt+40, 6)               // MajorOperatingSystemVersion
	mem.Write16(opt+42, 0)               // MinorOperatingSystemVersion
	mem.Write16(opt+48, 6)               // MajorSubsystemVersion
	mem.Write32(opt+56, uint32(sizeOfImage))  // SizeOfImage
	mem.Write32(opt+60, uint32(headerSize))   // SizeOfHeaders
	mem.Write16(opt+68, 3)               // Subsystem = WINDOWS_CUI
	mem.Write16(opt+70, 0x0160)          // DllCharacteristics (DYNAMIC_BASE | NX_COMPAT | HIGH_ENTROPY_VA)
	mem.Write32(opt+108, 16)             // NumberOfRvaAndSizes

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
	mem.Write32(secBase2+8, edataSize)          // VirtualSize
	mem.Write32(secBase2+12, uint32(edataRVA))  // VirtualAddress
	mem.Write32(secBase2+16, edataSize)          // SizeOfRawData
	mem.Write32(secBase2+20, uint32(edataRVA))  // PointerToRawData
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
		synth.ExportOrds[uint16(i)] = stubAddr // identity ordinal mapping
	}

	// --- Write .edata section: export directory ---
	exportDir := baseAddr + edataRVA
	funcTableRVA := edataRVA + 40
	nameTableRVA := funcTableRVA + uint64(numExports)*4
	ordTableRVA := nameTableRVA + uint64(numExports)*4
	nameStringsRVA := ordTableRVA + uint64(numExports)*2

	// IMAGE_EXPORT_DIRECTORY
	mem.Write32(exportDir+12, uint32(edataRVA+40+uint64(numExports)*10)) // Name RVA (DLL name, placed after tables)
	mem.Write32(exportDir+16, 0)            // OrdinalBase
	mem.Write32(exportDir+20, numExports)   // NumberOfFunctions
	mem.Write32(exportDir+24, numExports)   // NumberOfNames
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
		mem.Write32(baseAddr+funcTableRVA+uint64(i)*4, uint32(funcRVA))

		// Name RVA
		mem.Write32(baseAddr+nameTableRVA+uint64(i)*4, uint32(nameStrCursor))

		// Ordinal (identity mapping: ordinal[i] = i)
		mem.Write16(baseAddr+ordTableRVA+uint64(i)*2, uint16(i))

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

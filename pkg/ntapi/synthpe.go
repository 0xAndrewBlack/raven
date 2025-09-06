package ntapi

import (
	"encoding/binary"
	"fmt"

	"github.com/mirkobrombin/go-vm/pkg/loader"
	"github.com/mirkobrombin/go-vm/pkg/mmu"
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
	Name      string
	BaseAddr  uint64
	ImageSize uint64
	Exports   map[string]uint64 // name → guest address of stub
	StubIDs   map[uint64]uint32 // guest address → syscall ID
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

// ntapiExports lists the core NTAPI functions to stub in synthetic ntdll.dll.
// These are ordered by frequency of use in typical Windows applications.
var ntapiExports = []string{
	// File I/O
	"NtCreateFile",
	"NtOpenFile",
	"NtReadFile",
	"NtWriteFile",
	"NtClose",
	"NtQueryInformationFile",
	"NtSetInformationFile",
	"NtQueryDirectoryFile",
	"NtQueryDirectoryFileEx",
	"NtDeviceIoControlFile",
	"NtFsControlFile",
	"NtQueryVolumeInformationFile",
	"NtFlushBuffersFile",
	"NtDeleteFile",
	"NtCreateSection",
	"NtMapViewOfSection",
	"NtUnmapViewOfSection",

	// Registry
	"NtOpenKey",
	"NtOpenKeyEx",
	"NtCreateKey",
	"NtQueryValueKey",
	"NtSetValueKey",
	"NtDeleteKey",
	"NtDeleteValueKey",
	"NtEnumerateKey",
	"NtEnumerateValueKey",
	"NtQueryKey",
	"NtFlushKey",

	// Process / Thread
	"NtQueryInformationProcess",
	"NtSetInformationProcess",
	"NtQueryInformationThread",
	"NtSetInformationThread",
	"NtQuerySystemInformation",
	"NtQuerySystemInformationEx",
	"NtTerminateProcess",
	"NtTerminateThread",
	"NtCreateThread",
	"NtCreateThreadEx",
	"NtResumeThread",
	"NtSuspendThread",
	"NtGetContextThread",
	"NtSetContextThread",
	"NtQueueApcThread",

	// Virtual Memory
	"NtAllocateVirtualMemory",
	"NtFreeVirtualMemory",
	"NtProtectVirtualMemory",
	"NtQueryVirtualMemory",
	"NtReadVirtualMemory",
	"NtWriteVirtualMemory",
	"NtFlushVirtualMemory",

	// Synchronization
	"NtCreateEvent",
	"NtSetEvent",
	"NtResetEvent",
	"NtClearEvent",
	"NtPulseEvent",
	"NtWaitForSingleObject",
	"NtWaitForMultipleObjects",
	"NtSignalAndWaitForSingleObject",
	"NtCreateMutant",
	"NtReleaseMutant",
	"NtCreateSemaphore",
	"NtReleaseSemaphore",
	"NtCreateTimer",
	"NtSetTimer",
	"NtCancelTimer",
	"NtQueryTimer",
	"NtDelayExecution",
	"NtYieldExecution",
	"NtQueryPerformanceCounter",
	"NtQuerySystemTime",

	// Critical Sections (RTL)
	"RtlInitializeCriticalSection",
	"RtlInitializeCriticalSectionAndSpinCount",
	"RtlInitializeCriticalSectionEx",
	"RtlEnterCriticalSection",
	"RtlLeaveCriticalSection",
	"RtlDeleteCriticalSection",
	"RtlTryEnterCriticalSection",

	// SRW Locks (RTL)
	"RtlInitializeSRWLock",
	"RtlAcquireSRWLockExclusive",
	"RtlReleaseSRWLockExclusive",
	"RtlAcquireSRWLockShared",
	"RtlReleaseSRWLockShared",
	"RtlTryAcquireSRWLockExclusive",
	"RtlTryAcquireSRWLockShared",

	// Condition Variables
	"RtlInitializeConditionVariable",
	"RtlSleepConditionVariableSRW",
	"RtlSleepConditionVariableCS",
	"RtlWakeConditionVariable",
	"RtlWakeAllConditionVariable",

	// Heap
	"RtlAllocateHeap",
	"RtlFreeHeap",
	"RtlReAllocateHeap",
	"RtlSizeHeap",
	"RtlCreateHeap",
	"RtlDestroyHeap",

	// String / Unicode utilities
	"RtlInitUnicodeString",
	"RtlFreeUnicodeString",
	"RtlCompareUnicodeString",
	"RtlCopyUnicodeString",
	"RtlAnsiStringToUnicodeString",
	"RtlUnicodeStringToAnsiString",
	"RtlInitAnsiString",
	"RtlFreeAnsiString",
	"RtlUpcaseUnicodeString",
	"RtlDowncaseUnicodeString",

	// Misc
	"RtlGetVersion",
	"RtlNtStatusToDosError",
	"RtlSetLastWin32Error",
	"RtlGetLastWin32Error",
	"NtQueryObject",
	"NtDuplicateObject",
	"NtSetInformationObject",
	"NtQuerySecurityObject",
	"NtSetSecurityObject",

	// Token / Security
	"NtOpenProcessToken",
	"NtOpenThreadToken",
	"NtQueryInformationToken",
	"NtAdjustPrivilegesToken",

	// Error / Exception
	"RtlRaiseException",
	"RtlUnwind",
	"RtlUnwindEx",
	"RtlAddVectoredExceptionHandler",
	"RtlRemoveVectoredExceptionHandler",

	// DLL loading internals
	"LdrLoadDll",
	"LdrGetProcedureAddress",
	"LdrGetDllHandle",
	"LdrInitializeThunk",
	"LdrShutdownProcess",
	"LdrShutdownThread",

	// Image / Module
	"RtlImageNtHeader",
	"RtlImageDirectoryEntryToData",

	// Process parameters
	"RtlCreateProcessParameters",
	"RtlDestroyProcessParameters",
	"RtlNormalizeProcessParams",

	// Time
	"RtlTimeToSecondsSince1970",
	"RtlSecondsSince1970ToTime",
}

// win32uExports lists Win32k syscall stubs for win32u.dll.
var win32uExports = []string{
	"NtUserCreateWindowEx",
	"NtUserDestroyWindow",
	"NtUserShowWindow",
	"NtUserMoveWindow",
	"NtUserSetWindowPos",
	"NtUserGetClientRect",
	"NtUserGetWindowRect",
	"NtUserGetMessage",
	"NtUserPeekMessage",
	"NtUserDispatchMessage",
	"NtUserTranslateMessage",
	"NtUserSendMessage",
	"NtUserPostMessage",
	"NtUserDefWindowProc",
	"NtUserRegisterClassEx",
	"NtUserSetCursor",
	"NtUserGetDC",
	"NtUserReleaseDC",
	"NtUserBeginPaint",
	"NtUserEndPaint",
	"NtUserInvalidateRect",
	"NtUserUpdateWindow",
	"NtUserSetTimer",
	"NtUserKillTimer",
	"NtUserSetFocus",
	"NtUserGetForegroundWindow",
	"NtUserSetForegroundWindow",
	"NtUserGetKeyState",
	"NtUserGetAsyncKeyState",
	"NtUserGetCursorPos",
	"NtUserSetCapture",
	"NtUserReleaseCapture",
	"NtGdiCreateCompatibleDC",
	"NtGdiDeleteObjectApp",
	"NtGdiCreateDIBSection",
	"NtGdiBitBlt",
	"NtGdiStretchBlt",
	"NtGdiExtTextOutW",
	"NtGdiTextOutW",
	"NtGdiGetTextExtentPoint32W",
	"NtGdiSelectObject",
	"NtGdiCreateSolidBrush",
	"NtGdiCreatePen",
	"NtGdiPolyline",
	"NtGdiFillRect",
	"NtGdiRectangle",
	"NtGdiEllipse",
	"NtGdiSetTextColor",
	"NtGdiSetBkColor",
	"NtGdiSetBkMode",
	"NtGdiCreateFontIndirectW",
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
		Name:    name,
		Exports: make(map[string]uint64),
		StubIDs: make(map[uint64]uint32),
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
		ExportOrds: make(map[uint16]uint64),
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

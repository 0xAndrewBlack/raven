//go:build guest_windows

package ntapi

import (
	"encoding/binary"

	"github.com/mirkobrombin/Raven/pkg/mmu"
)

// Windows 10 x64 structure offsets (verified against phnt/Vergilius Project).

// TEB offsets (x86 / Win32).
const (
	Teb32Size = 0x1000

	Teb32ExceptionList      = 0x0000
	Teb32StackBase          = 0x0004
	Teb32StackLimit         = 0x0008
	Teb32SubSystemTib       = 0x000C
	Teb32FiberData          = 0x0010
	Teb32Self               = 0x0018
	Teb32EnvironmentPointer = 0x001C
	Teb32ProcessId          = 0x0020
	Teb32ThreadId           = 0x0024
	Teb32ActiveRpcHandle    = 0x0028
	Teb32ThreadLocalStorage = 0x002C
	Teb32PEB                = 0x0030
	Teb32LastErrorValue     = 0x0034
	Teb32CountCritSec       = 0x0038
	Teb32CurrentLocale      = 0x00C4
	Teb32TlsSlots           = 0x0E10 // 64 × 4 bytes
	Teb32TlsExpansionSlots  = 0x0F94
	Teb32FlsData            = 0x0FB4 // pointer to FLS slot array
	Teb32HeapBase           = 0x0FC0 // custom: inline heap base (matches Raven convention)
	Teb32HeapOffset         = 0x0FC4 // custom: inline heap bump offset
)

// PEB offsets (x86 / Win32).
const (
	Peb32Size = 0x480

	Peb32BeingDebugged        = 0x0002
	Peb32ImageBaseAddress     = 0x0008
	Peb32Ldr                  = 0x000C
	Peb32ProcessParameters    = 0x0010
	Peb32SubSystemData        = 0x0014
	Peb32ProcessHeap          = 0x0018
	Peb32FastPebLock          = 0x001C
	Peb32KernelCallbackTable  = 0x002C
	Peb32TlsBitmap            = 0x0040
	Peb32TlsBitmapBits        = 0x0044 // 2 × uint32
	Peb32NumberOfProcessors   = 0x0064
	Peb32NtGlobalFlag         = 0x0068
	Peb32OSMajorVersion       = 0x00A4
	Peb32OSMinorVersion       = 0x00A8
	Peb32OSBuildNumber        = 0x00AC
	Peb32OSPlatformId         = 0x00B0
	Peb32ImageSubsystem       = 0x00B4
	Peb32ImageSubsystemMajor  = 0x00B8
	Peb32SessionId            = 0x01D4
	Peb32FlsBitmap            = 0x020C
	Peb32FlsBitmapBits        = 0x0210 // 4 × uint32
	Peb32FlsListHead          = 0x0220 // LIST_ENTRY32
	Peb32FlsCallback          = 0x0228
	Peb32GdiSharedHandleTable = 0x0094
)

// LDR_DATA_TABLE_ENTRY offsets (x86).
const (
	Ldr32EntrySize               = 0x80
	Ldr32EntryInLoadOrderLinks   = 0x0000
	Ldr32EntryInMemoryOrderLinks = 0x0008
	Ldr32EntryInInitOrderLinks   = 0x0010
	Ldr32EntryDllBase            = 0x0018
	Ldr32EntryEntryPoint         = 0x001C
	Ldr32EntrySizeOfImage        = 0x0020
	Ldr32EntryFullDllName        = 0x0024 // UNICODE_STRING32
	Ldr32EntryBaseDllName        = 0x002C // UNICODE_STRING32
)

// UNICODE_STRING32 layout.
const (
	UnicodeString32Length    = 0x00 // USHORT
	UnicodeString32MaxLength = 0x02 // USHORT
	UnicodeString32Buffer    = 0x04 // DWORD
	UnicodeString32Size      = 0x08
)

// x86 RTL_USER_PROCESS_PARAMETERS offsets.
const (
	ProcessParams32Size            = 0x200
	ProcessParams32StdInputHandle  = 0x0018
	ProcessParams32StdOutputHandle = 0x001C
	ProcessParams32StdErrorHandle  = 0x0020
	ProcessParams32CurrentDir      = 0x0024 // CURDIR32 (UNICODE_STRING32 + HANDLE)
	ProcessParams32ImagePathName   = 0x0038 // UNICODE_STRING32
	ProcessParams32CommandLine     = 0x0040 // UNICODE_STRING32
	ProcessParams32Environment     = 0x0048 // DWORD pointer
)

// LDR_DATA32 offsets (x86).
const (
	Ldr32DataSize                = 0x30
	Ldr32Length                  = 0x0000
	Ldr32Initialized             = 0x0004
	Ldr32InLoadOrderModuleList   = 0x000C // LIST_ENTRY32
	Ldr32InMemoryOrderModuleList = 0x0014
	Ldr32InInitOrderModuleList   = 0x001C
)

// TEB offsets (x64).
const (
	TebSize = 0x1838

	TebNtTib               = 0x0000 // NT_TIB (ExceptionList, StackBase, StackLimit, ...)
	TebExceptionList       = 0x0000 // EXCEPTION_REGISTRATION_RECORD*
	TebStackBase           = 0x0008
	TebStackLimit          = 0x0010
	TebSubSystemTib        = 0x0018
	TebFiberData           = 0x0020
	TebSelf                = 0x0030 // pointer to TEB itself
	TebEnvironmentPointer  = 0x0038
	TebClientId            = 0x0040 // CLIENT_ID (ProcessId, ThreadId)
	TebProcessId           = 0x0040
	TebThreadId            = 0x0048
	TebActiveRpcHandle     = 0x0050
	TebThreadLocalStorage  = 0x0058 // pointer to TLS array
	TebPEB                 = 0x0060 // pointer to PEB
	TebLastErrorValue      = 0x0068
	TebCountOfOwnedCritSec = 0x006C
	TebCsrClientThread     = 0x0070
	TebWin32ThreadInfo     = 0x0078
	TebCurrentLocale       = 0x0108
	TebStaticUnicodeString = 0x0120 // UNICODE_STRING (Buffer at +0x0128)
	TebTlsSlots            = 0x1480 // 64 TLS slots (64 × 8 bytes = 0x200)
	TebTlsExpansionSlots   = 0x1780 // pointer to expanded TLS
	TebFlsData             = 0x17c8 // pointer to FLS slot array
	TebHeapBase            = 0x1800 // inline HeapAlloc: heap base address
	TebHeapOffset          = 0x1808 // inline HeapAlloc: current bump offset
)

// PEB offsets (x64).
const (
	PebSize = 0x7C8

	PebInheritedAddressSpace = 0x0000
	PebBeingDebugged         = 0x0002
	PebImageBaseAddress      = 0x0010
	PebLdr                   = 0x0018 // PEB_LDR_DATA*
	PebProcessParameters     = 0x0020 // RTL_USER_PROCESS_PARAMETERS*
	PebSubSystemData         = 0x0028
	PebProcessHeap           = 0x0030
	PebFastPebLock           = 0x0038
	PebAtlThunkSListPtr      = 0x0040
	PebKernelCallbackTable   = 0x0058
	PebApiSetMap             = 0x0068
	PebTlsExpansionCounter   = 0x0070
	PebTlsBitmap             = 0x0078 // PVOID → RTL_BITMAP*
	PebTlsBitmapBits         = 0x0080 // 2 × uint32 (bitmask for first 64 slots)
	PebAnsiCodePageData      = 0x00A0 // USHORT* to NLS code page data
	PebOemCodePageData       = 0x00A8 // USHORT* to NLS code page data
	PebUnicodeCaseTableData  = 0x00B0 // USHORT* to Unicode case mapping
	PebNumberOfProcessors    = 0x00B8
	PebNtGlobalFlag          = 0x00BC
	PebSessionId             = 0x02C0
	PebOSMajorVersion        = 0x0118
	PebOSMinorVersion        = 0x011C
	PebOSBuildNumber         = 0x0120
	PebOSPlatformId          = 0x0124
	PebImageSubsystem        = 0x0128
	PebImageSubsystemMajor   = 0x012C
	PebImageSubsystemMinor   = 0x0130

	PebFlsBitmap            = 0x0258 // PVOID → RTL_BITMAP*
	PebFlsBitmapBits        = 0x0260 // 4 × uint32 (bitmask for 128 FLS slots)
	PebFlsListHead          = 0x0270 // LIST_ENTRY
	PebFlsCallback          = 0x0280 // PVOID*
	PebGdiSharedHandleTable = 0x00F8 // PVOID → GDI shared handle table
	PebGdiHandleBuffer      = 0x00D4 // 34 × ULONG (starting offset)
)

// LDR_DATA offsets.
const (
	LdrDataSize                = 0x58
	LdrLength                  = 0x0000
	LdrInitialized             = 0x0004
	LdrInLoadOrderModuleList   = 0x0010 // LIST_ENTRY (Flink, Blink)
	LdrInMemoryOrderModuleList = 0x0020
	LdrInInitOrderModuleList   = 0x0030
)

// LDR_DATA_TABLE_ENTRY offsets (x64).
const (
	LdrEntrySize               = 0x120
	LdrEntryInLoadOrderLinks   = 0x0000
	LdrEntryInMemoryOrderLinks = 0x0010
	LdrEntryInInitOrderLinks   = 0x0020
	LdrEntryDllBase            = 0x0030
	LdrEntryEntryPoint         = 0x0038
	LdrEntrySizeOfImage        = 0x0040
	LdrEntryFullDllName        = 0x0048 // UNICODE_STRING
	LdrEntryBaseDllName        = 0x0058 // UNICODE_STRING
	LdrEntryFlags              = 0x0068
	LdrEntryLoadCount          = 0x006C
)

// UNICODE_STRING layout.
const (
	UnicodeStringLength    = 0x00 // USHORT
	UnicodeStringMaxLength = 0x02 // USHORT
	UnicodeStringBuffer    = 0x08 // PWSTR (8-byte aligned on x64)
	UnicodeStringSize      = 0x10
)

// RTL_USER_PROCESS_PARAMETERS offsets.
const (
	ProcessParamsSize            = 0x400
	ProcessParamsMaxLength       = 0x0000
	ProcessParamsLength          = 0x0004
	ProcessParamsFlags           = 0x0008
	ProcessParamsConsoleHandle   = 0x0010
	ProcessParamsConsoleFlags    = 0x0018
	ProcessParamsStdInputHandle  = 0x0020
	ProcessParamsStdOutputHandle = 0x0028
	ProcessParamsStdErrorHandle  = 0x0030
	ProcessParamsCurrentDir      = 0x0038 // CURDIR (UNICODE_STRING + HANDLE)
	ProcessParamsImagePathName   = 0x0060 // UNICODE_STRING
	ProcessParamsCommandLine     = 0x0070 // UNICODE_STRING
	ProcessParamsEnvironment     = 0x0080 // pointer to environment block
)

// ProcessInit holds parameters for initializing PEB/TEB.
type ProcessInit struct {
	ImageBase   uint64
	ImageSize   uint64
	EntryPoint  uint64
	CommandLine string
	ImagePath   string
	CurrentDir  string
	Environment []string // "KEY=VALUE" pairs
	ProcessId   uint32
	ThreadId    uint32
	StackBase   uint64
	StackLimit  uint64
	Is32        bool // PE32 (x86) process
}

// ModuleInfo describes a loaded module for the LDR list.
type ModuleInfo struct {
	Name      string // e.g. "kernel32.dll"
	FullPath  string // e.g. "C:\\Windows\\System32\\kernel32.dll"
	BaseAddr  uint64
	ImageSize uint64
	Entry     uint64
}

// ProcessState holds allocated guest addresses for PEB/TEB structures.
type ProcessState struct {
	PEBAddr                  uint64
	TEBAddr                  uint64
	LdrDataAddr              uint64
	ProcessParamsAddr        uint64
	EnvironmentAddr          uint64
	ModuleListAddr           uint64 // base of LDR_DATA_TABLE_ENTRY array
	GdiTableAddr             uint64 // GDI shared handle table base
	Win32kTrampoline         uint64 // guest addr of the KUSER_SHARED_DATA->SystemCall vmcall stub (PE32)
	LastError                uint32
	ImagePath                string // Win32 image path, e.g. "C:\app\program.exe"
	ProcessId                uint32
	ThreadId                 uint32
	UnhandledExceptionFilter uint64
	Is32                     bool // PE32 (x86) process

	// HeapAlloc/HeapFree are set by registerAutoSynthHandlers to route
	// RtlAllocateHeap / RtlFreeHeap through the shared bump-allocator.
	HeapAlloc func(size uint64, zeroInit bool) uint64
	HeapFree  func(ptr uint64)
	HeapSize  func(ptr uint64) uint64
}

// InitProcess allocates and populates PEB, TEB, and supporting structures.
func InitProcess(mem *mmu.MMU, init *ProcessInit, modules []ModuleInfo) (*ProcessState, error) {
	if init.Is32 {
		return initProcess32(mem, init, modules)
	}
	state := &ProcessState{}

	// Allocate all structures in one contiguous region for simplicity.
	// Layout: TEB | PEB | LDR_DATA | PROCESS_PARAMS | ENV | MODULE_ENTRIES | STRINGS
	totalModEntries := uint64(len(modules)) * LdrEntrySize
	stringPoolSize := uint64(4096) // buffer for UNICODE_STRING data
	totalSize := uint64(TebSize) + uint64(PebSize) + uint64(LdrDataSize) +
		uint64(ProcessParamsSize) + 4096 + totalModEntries + stringPoolSize

	regionBase := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite)

	tebAddr := regionBase
	pebAddr := tebAddr + TebSize
	ldrAddr := pebAddr + uint64(PebSize)
	paramsAddr := ldrAddr + LdrDataSize
	envAddr := paramsAddr + ProcessParamsSize
	modBase := envAddr + 4096
	strPool := modBase + totalModEntries

	state.TEBAddr = tebAddr
	state.PEBAddr = pebAddr
	state.LdrDataAddr = ldrAddr
	state.ProcessParamsAddr = paramsAddr
	state.EnvironmentAddr = envAddr
	state.ModuleListAddr = modBase

	// --- TEB ---
	mem.Write64(tebAddr+TebSelf, tebAddr)
	mem.Write64(tebAddr+TebPEB, pebAddr)
	mem.Write64(tebAddr+TebStackBase, init.StackBase)
	mem.Write64(tebAddr+TebStackLimit, init.StackLimit)
	mem.Write32(tebAddr+TebProcessId, init.ProcessId)
	mem.Write32(tebAddr+TebThreadId, init.ThreadId)
	mem.Write64(tebAddr+TebExceptionList, 0xFFFFFFFFFFFFFFFF) // no exception handler

	// --- PEB ---
	mem.Write8(pebAddr+PebBeingDebugged, 0)
	mem.Write64(pebAddr+PebImageBaseAddress, init.ImageBase)
	mem.Write64(pebAddr+PebLdr, ldrAddr)
	mem.Write64(pebAddr+PebProcessParameters, paramsAddr)

	// Allocate process heap - Wine DLLs read PEB.ProcessHeap directly
	processHeap := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
	mem.Write64(pebAddr+PebProcessHeap, processHeap)

	// Initialize FastPebLock (RTL_CRITICAL_SECTION at PEB+0x38)
	// RTL_CRITICAL_SECTION: DebugInfo(8) + LockCount(4) + RecursionCount(4) + OwningThread(8) + LockSemaphore(8) + SpinCount(8) = 40 bytes
	// Wine's RtlAcquirePebLock uses PEB->FastPebLock which is a pointer to a critical section
	fastPebLock := mem.Mmap(0, 64, mmu.PermRead|mmu.PermWrite)
	mem.Write64(pebAddr+PebFastPebLock, fastPebLock)
	mem.Write32(fastPebLock+4, 0xFFFFFFFF) // LockCount = -1 (unlocked)

	// Initialize TlsBitmap - RTL_BITMAP { SizeOfBitMap: ULONG, Buffer: PULONG }
	// Wine's TlsAlloc reads PEB->TlsBitmap via RtlFindClearBitsAndSet.
	// TlsBitmapBits is inline in PEB at offset 0x080 (2 × ULONG = 64 bits for 64 TLS slots).
	tlsBitmap := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
	mem.Write32(tlsBitmap, 64)                         // SizeOfBitMap = 64
	mem.Write64(tlsBitmap+8, pebAddr+PebTlsBitmapBits) // Buffer → PEB.TlsBitmapBits
	mem.Write64(pebAddr+PebTlsBitmap, tlsBitmap)
	// TlsBitmapBits starts as all-zero (all slots free)

	// Initialize FlsBitmap - same RTL_BITMAP for FLS (128 slots, 4 × ULONG)
	flsBitmap := mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
	mem.Write32(flsBitmap, 128)                        // SizeOfBitMap = 128
	mem.Write64(flsBitmap+8, pebAddr+PebFlsBitmapBits) // Buffer → PEB.FlsBitmapBits
	mem.Write64(pebAddr+PebFlsBitmap, flsBitmap)
	// Reserve FLS index 0 (it's always reserved)
	mem.Write32(pebAddr+PebFlsBitmapBits, 1) // bit 0 set = index 0 reserved
	// FlsListHead: circular doubly-linked list pointing to itself
	mem.Write64(pebAddr+PebFlsListHead, pebAddr+PebFlsListHead)
	mem.Write64(pebAddr+PebFlsListHead+8, pebAddr+PebFlsListHead)

	// GDI shared handle table: 0x4000 entries × 24 bytes each.
	// gdi32 indexes this by handle & 0xFFFF; entry size = 24 (8+4+2+1+1+8).
	// Type byte at entry+0x0E: 0 = unused slot.
	gdiTableSize := uint64(0x4000 * 24) // 393216 bytes
	gdiTable := mem.Mmap(0, gdiTableSize, mmu.PermRead|mmu.PermWrite)
	mem.Write64(pebAddr+PebGdiSharedHandleTable, gdiTable)
	state.GdiTableAddr = gdiTable

	// Pre-populate stock screen DC at index 52 - gdi32 looks up this fixed
	// entry when CreateCompatibleDC(NULL) is called.
	const gdiEntrySize = 24
	stockDCEntry := gdiTable + 52*gdiEntrySize
	mem.Write8(stockDCEntry+0x0E, 0x01) // type = OBJ_DC

	mem.Write32(pebAddr+PebNumberOfProcessors, 4)
	mem.Write32(pebAddr+PebNtGlobalFlag, 0)
	// Spoof Windows 10 22H2
	mem.Write32(pebAddr+PebOSMajorVersion, 10)
	mem.Write32(pebAddr+PebOSMinorVersion, 0)
	mem.Write16(pebAddr+PebOSBuildNumber, 19045)
	mem.Write32(pebAddr+PebOSPlatformId, 2)   // VER_PLATFORM_WIN32_NT
	mem.Write32(pebAddr+PebImageSubsystem, 3) // IMAGE_SUBSYSTEM_WINDOWS_CUI

	// --- RTL_USER_PROCESS_PARAMETERS ---
	strCursor := strPool
	writeUS := func(addr uint64, s string) {
		utf16 := encodeUTF16LE(s)
		byteLen := uint16(len(utf16))
		mem.Write16(addr+UnicodeStringLength, byteLen)
		mem.Write16(addr+UnicodeStringMaxLength, byteLen+2)
		mem.Write64(addr+UnicodeStringBuffer, strCursor)
		mem.WriteBytes(strCursor, utf16)
		mem.Write16(strCursor+uint64(byteLen), 0) // null terminator
		strCursor += uint64(byteLen) + 2
		strCursor = (strCursor + 7) & ^uint64(7) // align to 8
	}

	writeUS(paramsAddr+ProcessParamsImagePathName, init.ImagePath)
	writeUS(paramsAddr+ProcessParamsCommandLine, init.CommandLine)
	writeUS(paramsAddr+ProcessParamsCurrentDir, init.CurrentDir)

	// Standard handles (virtual)
	mem.Write64(paramsAddr+ProcessParamsStdInputHandle, 0xFFFFFFF6)  // STD_INPUT_HANDLE sentinel
	mem.Write64(paramsAddr+ProcessParamsStdOutputHandle, 0xFFFFFFF5) // STD_OUTPUT_HANDLE
	mem.Write64(paramsAddr+ProcessParamsStdErrorHandle, 0xFFFFFFF4)  // STD_ERROR_HANDLE

	// Environment block (double-null terminated UTF-16LE)
	envData := buildEnvironmentBlock(init.Environment)
	mem.WriteBytes(envAddr, envData)
	mem.Write64(paramsAddr+ProcessParamsEnvironment, envAddr)

	// --- PEB_LDR_DATA ---
	// The three lists are circular doubly-linked. Each list's head is in PEB_LDR_DATA.
	loadOrderHead := ldrAddr + LdrInLoadOrderModuleList
	memOrderHead := ldrAddr + LdrInMemoryOrderModuleList
	initOrderHead := ldrAddr + LdrInInitOrderModuleList

	mem.Write32(ldrAddr+LdrLength, uint32(LdrDataSize))
	mem.Write8(ldrAddr+LdrInitialized, 1)

	if len(modules) == 0 {
		// Empty lists: point to themselves
		mem.Write64(loadOrderHead, loadOrderHead)
		mem.Write64(loadOrderHead+8, loadOrderHead)
		mem.Write64(memOrderHead, memOrderHead)
		mem.Write64(memOrderHead+8, memOrderHead)
		mem.Write64(initOrderHead, initOrderHead)
		mem.Write64(initOrderHead+8, initOrderHead)
	} else {
		// Build circular linked lists of LDR_DATA_TABLE_ENTRY
		for i, mod := range modules {
			entryAddr := modBase + uint64(i)*LdrEntrySize

			mem.Write64(entryAddr+LdrEntryDllBase, mod.BaseAddr)
			mem.Write64(entryAddr+LdrEntryEntryPoint, mod.Entry)
			mem.Write32(entryAddr+LdrEntrySizeOfImage, uint32(mod.ImageSize))
			mem.Write16(entryAddr+LdrEntryLoadCount, 0xFFFF) // pinned

			// BaseDllName
			writeUS(entryAddr+LdrEntryBaseDllName, mod.Name)
			// FullDllName
			writeUS(entryAddr+LdrEntryFullDllName, mod.FullPath)
		}

		// Wire up the three linked lists
		linkModuleList(mem, loadOrderHead, modBase, len(modules), LdrEntryInLoadOrderLinks)
		linkModuleList(mem, memOrderHead, modBase, len(modules), LdrEntryInMemoryOrderLinks)
		linkModuleList(mem, initOrderHead, modBase, len(modules), LdrEntryInInitOrderLinks)
	}

	return state, nil
}

// linkModuleList creates a circular doubly-linked list.
// head is the LIST_ENTRY in PEB_LDR_DATA.
// entries are at modBase + i*LdrEntrySize, using the given link offset.
func linkModuleList(mem *mmu.MMU, head, modBase uint64, count int, linkOff uint64) {
	if count == 0 {
		mem.Write64(head, head)
		mem.Write64(head+8, head)
		return
	}

	// head.Flink → first entry's link
	firstLink := modBase + linkOff
	lastLink := modBase + uint64(count-1)*LdrEntrySize + linkOff

	mem.Write64(head, firstLink)  // head.Flink = first
	mem.Write64(head+8, lastLink) // head.Blink = last

	for i := 0; i < count; i++ {
		entryLink := modBase + uint64(i)*LdrEntrySize + linkOff
		var prev, next uint64

		if i == 0 {
			prev = head
		} else {
			prev = modBase + uint64(i-1)*LdrEntrySize + linkOff
		}
		if i == count-1 {
			next = head
		} else {
			next = modBase + uint64(i+1)*LdrEntrySize + linkOff
		}

		mem.Write64(entryLink, next)   // Flink
		mem.Write64(entryLink+8, prev) // Blink
	}
}

// initProcess32 allocates and populates 32-bit (x86) PEB, TEB, and supporting structures.
func initProcess32(mem *mmu.MMU, init *ProcessInit, modules []ModuleInfo) (*ProcessState, error) {
	state := &ProcessState{Is32: true}

	totalModEntries := uint64(len(modules)) * Ldr32EntrySize
	stringPoolSize := uint64(4096)
	totalSize := uint64(Teb32Size) + uint64(Peb32Size) + uint64(Ldr32DataSize) +
		uint64(ProcessParams32Size) + 4096 + totalModEntries + stringPoolSize

	regionBase := mem.Mmap(0, totalSize, mmu.PermRead|mmu.PermWrite)

	tebAddr := regionBase
	pebAddr := tebAddr + Teb32Size
	ldrAddr := pebAddr + uint64(Peb32Size)
	paramsAddr := ldrAddr + Ldr32DataSize
	envAddr := paramsAddr + ProcessParams32Size
	modBase := envAddr + 4096
	strPool := modBase + totalModEntries

	state.TEBAddr = tebAddr
	state.PEBAddr = pebAddr
	state.LdrDataAddr = ldrAddr
	state.ProcessParamsAddr = paramsAddr
	state.EnvironmentAddr = envAddr
	state.ModuleListAddr = modBase

	// --- TEB32 ---
	mem.Write32(tebAddr+Teb32ExceptionList, 0xFFFFFFFF) // no SEH handler
	mem.Write32(tebAddr+Teb32StackBase, uint32(init.StackBase))
	mem.Write32(tebAddr+Teb32StackLimit, uint32(init.StackLimit))
	mem.Write32(tebAddr+Teb32Self, uint32(tebAddr))
	mem.Write32(tebAddr+Teb32PEB, uint32(pebAddr))
	mem.Write32(tebAddr+Teb32ProcessId, init.ProcessId)
	mem.Write32(tebAddr+Teb32ThreadId, init.ThreadId)
	mem.Write32(tebAddr+Teb32LastErrorValue, 0)

	// --- PEB32 ---
	mem.Write8(pebAddr+Peb32BeingDebugged, 0)
	mem.Write32(pebAddr+Peb32ImageBaseAddress, uint32(init.ImageBase))
	mem.Write32(pebAddr+Peb32Ldr, uint32(ldrAddr))
	mem.Write32(pebAddr+Peb32ProcessParameters, uint32(paramsAddr))

	processHeap := mem.Mmap(0, 0x1000, mmu.PermRead|mmu.PermWrite)
	mem.Write32(pebAddr+Peb32ProcessHeap, uint32(processHeap))

	fastPebLock := mem.Mmap(0, 32, mmu.PermRead|mmu.PermWrite)
	mem.Write32(pebAddr+Peb32FastPebLock, uint32(fastPebLock))
	mem.Write32(fastPebLock+4, 0xFFFFFFFF) // LockCount = -1

	// TLS bitmap
	tlsBitmap := mem.Mmap(0, 12, mmu.PermRead|mmu.PermWrite)
	mem.Write32(tlsBitmap, 64)                                   // SizeOfBitMap
	mem.Write32(tlsBitmap+4, uint32(pebAddr+Peb32TlsBitmapBits)) // Buffer
	mem.Write32(pebAddr+Peb32TlsBitmap, uint32(tlsBitmap))

	// FLS bitmap
	flsBitmap := mem.Mmap(0, 12, mmu.PermRead|mmu.PermWrite)
	mem.Write32(flsBitmap, 128)
	mem.Write32(flsBitmap+4, uint32(pebAddr+Peb32FlsBitmapBits))
	mem.Write32(pebAddr+Peb32FlsBitmap, uint32(flsBitmap))
	mem.Write32(pebAddr+Peb32FlsBitmapBits, 1) // reserve slot 0
	// FlsListHead: circular
	mem.Write32(pebAddr+Peb32FlsListHead, uint32(pebAddr+Peb32FlsListHead))
	mem.Write32(pebAddr+Peb32FlsListHead+4, uint32(pebAddr+Peb32FlsListHead))

	// GDI shared handle table. On 32-bit, GDI_TABLE_ENTRY is 16 bytes:
	//   KernelData(+0,4) ProcessId(+4,4) {FullUnique u16@+8, ObjectType u8@+0xA,
	//   Flags u8@+0xB} UserData(+0xC,4 → DC_ATTR). GDI_HANDLE_COUNT = 0x10000.
	const gdiEntry32 = 16
	gdiTableSize := uint64(0x10000 * gdiEntry32)
	gdiTable := mem.Mmap(0, gdiTableSize, mmu.PermRead|mmu.PermWrite)
	mem.Write32(pebAddr+Peb32GdiSharedHandleTable, uint32(gdiTable))
	state.GdiTableAddr = gdiTable
	stockDCEntry := gdiTable + 52*gdiEntry32
	mem.Write8(stockDCEntry+0x0A, 0x01) // ObjectType = DC

	mem.Write32(pebAddr+Peb32NumberOfProcessors, 4)
	mem.Write32(pebAddr+Peb32NtGlobalFlag, 0)
	mem.Write32(pebAddr+Peb32OSMajorVersion, 10)
	mem.Write32(pebAddr+Peb32OSMinorVersion, 0)
	mem.Write16(pebAddr+Peb32OSBuildNumber, 19045)
	mem.Write32(pebAddr+Peb32OSPlatformId, 2)
	mem.Write32(pebAddr+Peb32ImageSubsystem, 2) // IMAGE_SUBSYSTEM_WINDOWS_GUI

	// --- RTL_USER_PROCESS_PARAMETERS (32-bit) ---
	strCursor := strPool
	writeUS32 := func(addr uint64, s string) {
		utf16 := encodeUTF16LE(s)
		byteLen := uint16(len(utf16))
		mem.Write16(addr+UnicodeString32Length, byteLen)
		mem.Write16(addr+UnicodeString32MaxLength, byteLen+2)
		mem.Write32(addr+UnicodeString32Buffer, uint32(strCursor))
		mem.WriteBytes(strCursor, utf16)
		mem.Write16(strCursor+uint64(byteLen), 0)
		strCursor += uint64(byteLen) + 2
		strCursor = (strCursor + 3) & ^uint64(3) // align to 4
	}

	writeUS32(paramsAddr+ProcessParams32ImagePathName, init.ImagePath)
	writeUS32(paramsAddr+ProcessParams32CommandLine, init.CommandLine)
	writeUS32(paramsAddr+ProcessParams32CurrentDir, init.CurrentDir)

	mem.Write32(paramsAddr+ProcessParams32StdInputHandle, 0xFFFFFFF6)
	mem.Write32(paramsAddr+ProcessParams32StdOutputHandle, 0xFFFFFFF5)
	mem.Write32(paramsAddr+ProcessParams32StdErrorHandle, 0xFFFFFFF4)

	envData := buildEnvironmentBlock(init.Environment)
	mem.WriteBytes(envAddr, envData)
	mem.Write32(paramsAddr+ProcessParams32Environment, uint32(envAddr))

	// --- PEB_LDR_DATA32 ---
	loadOrderHead := ldrAddr + Ldr32InLoadOrderModuleList
	memOrderHead := ldrAddr + Ldr32InMemoryOrderModuleList
	initOrderHead := ldrAddr + Ldr32InInitOrderModuleList

	mem.Write32(ldrAddr+Ldr32Length, uint32(Ldr32DataSize))
	mem.Write8(ldrAddr+Ldr32Initialized, 1)

	if len(modules) == 0 {
		mem.Write32(loadOrderHead, uint32(loadOrderHead))
		mem.Write32(loadOrderHead+4, uint32(loadOrderHead))
		mem.Write32(memOrderHead, uint32(memOrderHead))
		mem.Write32(memOrderHead+4, uint32(memOrderHead))
		mem.Write32(initOrderHead, uint32(initOrderHead))
		mem.Write32(initOrderHead+4, uint32(initOrderHead))
	} else {
		for i, mod := range modules {
			entryAddr := modBase + uint64(i)*Ldr32EntrySize
			mem.Write32(entryAddr+Ldr32EntryDllBase, uint32(mod.BaseAddr))
			mem.Write32(entryAddr+Ldr32EntryEntryPoint, uint32(mod.Entry))
			mem.Write32(entryAddr+Ldr32EntrySizeOfImage, uint32(mod.ImageSize))
			mem.Write16(entryAddr+Ldr32EntryBaseDllName+6, 0xFFFF) // LoadCount
			writeUS32(entryAddr+Ldr32EntryBaseDllName, mod.Name)
			writeUS32(entryAddr+Ldr32EntryFullDllName, mod.FullPath)
		}
		linkModuleList32(mem, loadOrderHead, modBase, len(modules), Ldr32EntryInLoadOrderLinks)
		linkModuleList32(mem, memOrderHead, modBase, len(modules), Ldr32EntryInMemoryOrderLinks)
		linkModuleList32(mem, initOrderHead, modBase, len(modules), Ldr32EntryInInitOrderLinks)
	}

	return state, nil
}

// linkModuleList32 creates a circular doubly-linked list with 32-bit pointers.
func linkModuleList32(mem *mmu.MMU, head, modBase uint64, count int, linkOff uint64) {
	if count == 0 {
		mem.Write32(head, uint32(head))
		mem.Write32(head+4, uint32(head))
		return
	}
	firstLink := modBase + linkOff
	lastLink := modBase + uint64(count-1)*Ldr32EntrySize + linkOff
	mem.Write32(head, uint32(firstLink))
	mem.Write32(head+4, uint32(lastLink))
	for i := 0; i < count; i++ {
		entryLink := modBase + uint64(i)*Ldr32EntrySize + linkOff
		var prev, next uint64
		if i == 0 {
			prev = head
		} else {
			prev = modBase + uint64(i-1)*Ldr32EntrySize + linkOff
		}
		if i == count-1 {
			next = head
		} else {
			next = modBase + uint64(i+1)*Ldr32EntrySize + linkOff
		}
		mem.Write32(entryLink, uint32(next))
		mem.Write32(entryLink+4, uint32(prev))
	}
}

// encodeUTF16LE converts a Go string to UTF-16LE bytes.
func encodeUTF16LE(s string) []byte {
	buf := make([]byte, 0, len(s)*2)
	for _, r := range s {
		if r > 0xFFFF {
			// Surrogate pair for characters outside BMP
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			buf = append(buf, byte(hi), byte(hi>>8))
			buf = append(buf, byte(lo), byte(lo>>8))
		} else {
			buf = append(buf, byte(r), byte(r>>8))
		}
	}
	return buf
}

// decodeUTF16LE converts UTF-16LE bytes to a Go string.
func decodeUTF16LE(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	runes := make([]rune, 0, len(data)/2)
	for i := 0; i+1 < len(data); i += 2 {
		code := binary.LittleEndian.Uint16(data[i:])
		if code == 0 {
			break
		}
		runes = append(runes, rune(code))
	}
	return string(runes)
}

// buildEnvironmentBlock creates a double-null-terminated UTF-16LE environment.
func buildEnvironmentBlock(env []string) []byte {
	var buf []byte
	for _, e := range env {
		buf = append(buf, encodeUTF16LE(e)...)
		buf = append(buf, 0, 0) // null terminator for each entry
	}
	buf = append(buf, 0, 0) // final double-null
	return buf
}

// ReadUnicodeString reads a UNICODE_STRING structure from guest memory.
func ReadUnicodeString(mem *mmu.MMU, addr uint64) (string, error) {
	length, err := mem.Read16(addr + UnicodeStringLength)
	if err != nil {
		return "", err
	}
	var bufPtr uint64
	if mem.Mode32 {
		ptr32, perr := mem.Read32(addr + UnicodeString32Buffer)
		if perr != nil {
			return "", perr
		}
		bufPtr = uint64(ptr32)
	} else {
		bufPtr, err = mem.Read64(addr + UnicodeStringBuffer)
		if err != nil {
			return "", err
		}
	}
	if length == 0 || bufPtr == 0 {
		return "", nil
	}
	data, err := mem.ReadBytes(bufPtr, int(length))
	if err != nil {
		return "", err
	}
	return decodeUTF16LE(data), nil
}

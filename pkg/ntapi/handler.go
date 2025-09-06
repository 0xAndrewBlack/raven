package ntapi

import (
	"encoding/binary"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/mirkobrombin/go-vm/pkg/mmu"
)

// NTSTATUS codes.
const (
	StatusSuccess              uint32 = 0x00000000
	StatusInformationLength    uint32 = 0x00000004
	StatusBufferOverflow       uint32 = 0x80000005
	StatusNoMoreEntries        uint32 = 0x8000001A
	StatusNoMoreFiles          uint32 = 0x80000006
	StatusObjectNameNotFound   uint32 = 0xC0000034
	StatusObjectNameInvalid    uint32 = 0xC0000033
	StatusObjectPathNotFound   uint32 = 0xC000003A
	StatusNotImplemented       uint32 = 0xC0000002
	StatusInvalidHandle        uint32 = 0xC0000008
	StatusInvalidParameter     uint32 = 0xC000000D
	StatusAccessDenied         uint32 = 0xC0000022
	StatusBufferTooSmall       uint32 = 0xC0000023
	StatusNoSuchFile           uint32 = 0xC000000F
	StatusNoMemory             uint32 = 0xC0000017
	StatusObjectTypeMismatch   uint32 = 0xC0000024
	StatusKeyNotFound          uint32 = 0xC0000225
	StatusPending              uint32 = 0x00000103
	StatusTimeout              uint32 = 0x00000102
	StatusWait0                uint32 = 0x00000000
	StatusAlerted              uint32 = 0x00000101
	StatusProcessIsTerminating uint32 = 0xC000010A
)

// File access and creation flags.
const (
	fileSupersede  = 0x00000000
	fileOpen       = 0x00000001
	fileCreate     = 0x00000002
	fileOpenIf     = 0x00000003
	fileOverwrite  = 0x00000004
	fileOverwriteIf = 0x00000005

	fileDirectoryFile     = 0x00000001
	fileNonDirectoryFile  = 0x00000040
	fileSynchronousIoNonalert = 0x00000020
)

// FileInformationClass values.
const (
	fileBasicInformation          = 4
	fileStandardInformation       = 5
	fileNameInformation           = 9
	filePositionInformation       = 14
	fileDispositionInformation    = 13
	fileBothDirectoryInformation  = 3
	fileAllInformation            = 18
)

// ======================== FILE I/O ========================

func handleNtCreateFile(ctx *TrapContext) uint32 {
	// NtCreateFile(FileHandle*, DesiredAccess, ObjectAttributes*, IoStatusBlock*,
	//              AllocationSize*, FileAttributes, ShareAccess, CreateDisposition,
	//              CreateOptions, EaBuffer*, EaLength)
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // desiredAccess
	objAttr := ctx.Arg(2)
	ioStatus := ctx.Arg(3)
	createDisp := ctx.Arg(5) // stack arg
	createOpts := ctx.Arg(6) // stack arg

	path, err := ResolveObjectPath(ctx, objAttr)
	if err != nil {
		return StatusObjectPathNotFound
	}

	if ctx.Trace {
		fmt.Printf("  NtCreateFile: path=%q disp=%d opts=0x%x\n", path, createDisp, createOpts)
	}

	isDir := createOpts&fileDirectoryFile != 0

	// Map CreateDisposition to VFS open flags
	flags := 0 // O_RDWR
	switch uint32(createDisp) {
	case fileOpen:
		flags = 0 // open existing
	case fileCreate:
		flags = 0x40 | 0x80 // O_CREAT | O_EXCL
	case fileOpenIf:
		flags = 0x40 // O_CREAT
	case fileOverwrite, fileOverwriteIf, fileSupersede:
		flags = 0x40 | 0x200 // O_CREAT | O_TRUNC
	}

	if isDir {
		// Create directory if needed
		ctx.FS.MkdirAll(path)
	}

	fd, vfsErr := ctx.FS.OpenAt(-100, path, flags, 0644)
	if vfsErr != nil {
		if strings.Contains(vfsErr.Error(), "not found") || strings.Contains(vfsErr.Error(), "no such") {
			return StatusObjectNameNotFound
		}
		return StatusAccessDenied
	}

	fh := &FileHandle{FD: fd, Path: path}
	h := ctx.Handles.Alloc(fh)

	// Write handle to caller
	ctx.Mem.Write64(handlePtr, uint64(h))

	// IO_STATUS_BLOCK: Status=0, Information=FILE_OPENED (1) or FILE_CREATED (2)
	if ioStatus != 0 {
		ctx.Mem.Write32(ioStatus, StatusSuccess)
		info := uint64(1) // FILE_OPENED
		if uint32(createDisp) == fileCreate || uint32(createDisp) == fileOpenIf {
			info = 2 // FILE_CREATED
		}
		ctx.Mem.Write64(ioStatus+8, info)
	}

	return StatusSuccess
}

func handleNtOpenFile(ctx *TrapContext) uint32 {
	// Same as NtCreateFile but with fewer params
	return handleNtCreateFile(ctx)
}

func handleNtReadFile(ctx *TrapContext) uint32 {
	// NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock*, Buffer, Length, ByteOffset*, Key*)
	fileHandle := Handle(ctx.Arg(0))
	ioStatus := ctx.Arg(1) // actually arg4, but Windows ABI
	bufAddr := ctx.Arg(2)
	length := ctx.Arg(3)

	// Re-read from stack for proper positioning
	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		return StatusInvalidHandle
	}

	buf := make([]byte, length)
	n, err := ctx.FS.Read(fh.FD, buf)
	if err != nil {
		return StatusNoSuchFile
	}

	ctx.Mem.WriteBytes(bufAddr, buf[:n])

	if ioStatus != 0 {
		ctx.Mem.Write32(ioStatus, StatusSuccess)
		ctx.Mem.Write64(ioStatus+8, uint64(n))
	}

	return StatusSuccess
}

func handleNtWriteFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	ioStatus := ctx.Arg(1)
	bufAddr := ctx.Arg(2)
	length := ctx.Arg(3)

	// Handle standard output/error pseudo-handles
	if uint64(fileHandle) == 0xFFFFFFF5 || uint64(fileHandle) == 0xFFFFFFF4 {
		data, err := ctx.Mem.ReadBytes(bufAddr, int(length))
		if err != nil {
			return StatusInvalidParameter
		}
		fd := 1
		if uint64(fileHandle) == 0xFFFFFFF4 {
			fd = 2
		}
		ctx.FS.Write(fd, data)

		if ioStatus != 0 {
			ctx.Mem.Write32(ioStatus, StatusSuccess)
			ctx.Mem.Write64(ioStatus+8, length)
		}
		return StatusSuccess
	}

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		return StatusInvalidHandle
	}

	data, err := ctx.Mem.ReadBytes(bufAddr, int(length))
	if err != nil {
		return StatusInvalidParameter
	}

	n, writeErr := ctx.FS.Write(fh.FD, data)
	if writeErr != nil {
		return StatusAccessDenied
	}

	if ioStatus != 0 {
		ctx.Mem.Write32(ioStatus, StatusSuccess)
		ctx.Mem.Write64(ioStatus+8, uint64(n))
	}

	return StatusSuccess
}

func handleNtClose(ctx *TrapContext) uint32 {
	handle := Handle(ctx.Arg(0))

	// Check if it's a file handle and close the VFS fd
	fh := ctx.Handles.GetFile(handle)
	if fh != nil {
		ctx.FS.Close(fh.FD)
	}

	if !ctx.Handles.Close(handle) {
		return StatusInvalidHandle
	}
	return StatusSuccess
}

func handleNtQueryInformationFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	ioStatus := ctx.Arg(1)
	buffer := ctx.Arg(2)
	length := ctx.Arg(3)

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		return StatusInvalidHandle
	}

	node := ctx.FS.Stat(fh.FD)
	if node == nil {
		return StatusNoSuchFile
	}

	_ = length
	// We return FileStandardInformation by default (most commonly requested)
	// AllocationSize (8) + EndOfFile (8) + NumberOfLinks (4) + DeletePending (1) + Directory (1)
	if buffer != 0 {
		ctx.Mem.Write64(buffer+0, uint64(node.Size))      // AllocationSize
		ctx.Mem.Write64(buffer+8, uint64(node.Size))      // EndOfFile
		ctx.Mem.Write32(buffer+16, node.Nlink)             // NumberOfLinks
		dir := uint8(0)
		if node.IsDir {
			dir = 1
		}
		ctx.Mem.Write8(buffer+20, 0)    // DeletePending
		ctx.Mem.Write8(buffer+21, dir)  // Directory
	}

	if ioStatus != 0 {
		ctx.Mem.Write32(ioStatus, StatusSuccess)
		ctx.Mem.Write64(ioStatus+8, 24)
	}

	return StatusSuccess
}

func handleNtSetInformationFile(ctx *TrapContext) uint32 {
	return StatusSuccess // stub
}

func handleNtQueryDirectoryFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	_ = ctx.Arg(1) // ioStatus
	buffer := ctx.Arg(2)
	length := ctx.Arg(3)

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		return StatusInvalidHandle
	}

	entries := ctx.FS.Getdents64(fh.FD)
	if len(entries) == 0 {
		return StatusNoMoreFiles
	}

	// Write FileBothDirectoryInformation entries
	offset := uint64(0)
	for i, entry := range entries {
		nameUTF16 := encodeUTF16LE(entry.Name)
		entrySize := uint64(104 + len(nameUTF16)) // base struct + filename
		entrySize = (entrySize + 7) & ^uint64(7)  // align to 8

		if offset+entrySize > length {
			break
		}

		addr := buffer + offset

		// NextEntryOffset
		if i < len(entries)-1 {
			ctx.Mem.Write32(addr+0, uint32(entrySize))
		} else {
			ctx.Mem.Write32(addr+0, 0) // last entry
		}
		// FileIndex
		ctx.Mem.Write32(addr+4, uint32(i))
		// EndOfFile
		ctx.Mem.Write64(addr+40, uint64(entry.Size))
		// AllocationSize
		ctx.Mem.Write64(addr+48, uint64(entry.Size))
		// FileAttributes
		attrs := uint32(0x80) // FILE_ATTRIBUTE_NORMAL
		if entry.IsDir {
			attrs = 0x10 // FILE_ATTRIBUTE_DIRECTORY
		}
		ctx.Mem.Write32(addr+56, attrs)
		// FileNameLength
		ctx.Mem.Write32(addr+60, uint32(len(nameUTF16)))
		// FileName (at offset 104)
		ctx.Mem.WriteBytes(addr+104, nameUTF16)

		offset += entrySize
	}

	return StatusSuccess
}

func handleNtQueryVolumeInformationFile(ctx *TrapContext) uint32 {
	return StatusSuccess // stub
}

func handleNtDeleteFile(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleNtFlushBuffersFile(ctx *TrapContext) uint32 {
	return StatusSuccess
}

// ======================== REGISTRY ========================

func handleNtOpenKey(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // desiredAccess
	objAttr := ctx.Arg(2)

	_, name, _, err := ReadObjectAttributes(ctx, objAttr)
	if err != nil {
		return StatusObjectNameInvalid
	}

	key := ctx.Reg.OpenKey(name)
	if key == nil {
		if ctx.Trace {
			fmt.Printf("  NtOpenKey: NOT FOUND: %q\n", name)
		}
		return StatusKeyNotFound
	}

	h := ctx.Handles.Alloc(&RegistryKeyHandle{Key: key})
	ctx.Mem.Write64(handlePtr, uint64(h))

	if ctx.Trace {
		fmt.Printf("  NtOpenKey: opened %q → handle=0x%x\n", name, h)
	}

	return StatusSuccess
}

func handleNtOpenKeyEx(ctx *TrapContext) uint32 {
	return handleNtOpenKey(ctx)
}

func handleNtCreateKey(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // desiredAccess
	objAttr := ctx.Arg(2)

	_, name, _, err := ReadObjectAttributes(ctx, objAttr)
	if err != nil {
		return StatusObjectNameInvalid
	}

	key := ctx.Reg.CreateKey(name)
	h := ctx.Handles.Alloc(&RegistryKeyHandle{Key: key})
	ctx.Mem.Write64(handlePtr, uint64(h))

	return StatusSuccess
}

func handleNtQueryValueKey(ctx *TrapContext) uint32 {
	keyHandle := Handle(ctx.Arg(0))
	valueNameAddr := ctx.Arg(1) // PUNICODE_STRING
	_ = ctx.Arg(2)              // KeyValueInformationClass
	buffer := ctx.Arg(3)        // stack arg 0

	rk := ctx.Handles.GetRegKey(keyHandle)
	if rk == nil {
		return StatusInvalidHandle
	}

	valueName, err := ReadUnicodeString(ctx.Mem, valueNameAddr)
	if err != nil {
		return StatusObjectNameInvalid
	}

	val, ok := rk.Key.Values[valueName]
	if !ok {
		// Case-insensitive search
		for k, v := range rk.Key.Values {
			if strings.EqualFold(k, valueName) {
				val = v
				ok = true
				break
			}
		}
	}
	if !ok {
		return StatusObjectNameNotFound
	}

	if buffer != 0 {
		// KEY_VALUE_PARTIAL_INFORMATION: TitleIndex(4) + Type(4) + DataLength(4) + Data
		ctx.Mem.Write32(buffer+0, 0)                      // TitleIndex
		ctx.Mem.Write32(buffer+4, val.Type)                // Type
		ctx.Mem.Write32(buffer+8, uint32(len(val.Data)))   // DataLength
		ctx.Mem.WriteBytes(buffer+12, val.Data)            // Data
	}

	return StatusSuccess
}

func handleNtSetValueKey(ctx *TrapContext) uint32 {
	keyHandle := Handle(ctx.Arg(0))
	valueNameAddr := ctx.Arg(1)
	_ = ctx.Arg(2) // TitleIndex
	valType := uint32(ctx.Arg(3))

	rk := ctx.Handles.GetRegKey(keyHandle)
	if rk == nil {
		return StatusInvalidHandle
	}

	valueName, err := ReadUnicodeString(ctx.Mem, valueNameAddr)
	if err != nil {
		return StatusObjectNameInvalid
	}

	// Stack args: DataPtr and DataSize
	// For now, accept the write but we can't easily read stack args beyond 3
	rk.Key.Values[valueName] = &RegistryValue{
		Name: valueName,
		Type: valType,
		Data: nil, // simplified
	}

	return StatusSuccess
}

func handleNtDeleteKey(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtDeleteValueKey(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtEnumerateKey(ctx *TrapContext) uint32 {
	keyHandle := Handle(ctx.Arg(0))
	index := uint32(ctx.Arg(1))
	_ = ctx.Arg(2) // KeyInformationClass
	buffer := ctx.Arg(3)

	rk := ctx.Handles.GetRegKey(keyHandle)
	if rk == nil {
		return StatusInvalidHandle
	}

	names := ctx.Reg.EnumerateKeys(rk.Key)
	if int(index) >= len(names) {
		return StatusNoMoreEntries
	}

	name := names[index]
	child := rk.Key.Children[strings.ToUpper(name)]
	if child != nil {
		name = child.Name // use original case
	}

	// KEY_BASIC_INFORMATION
	if buffer != 0 {
		nameUTF16 := encodeUTF16LE(name)
		ctx.Mem.Write64(buffer+0, 0)                      // LastWriteTime
		ctx.Mem.Write32(buffer+8, 0)                       // TitleIndex
		ctx.Mem.Write32(buffer+12, uint32(len(nameUTF16))) // NameLength
		ctx.Mem.WriteBytes(buffer+16, nameUTF16)           // Name
	}

	return StatusSuccess
}

func handleNtEnumerateValueKey(ctx *TrapContext) uint32 {
	keyHandle := Handle(ctx.Arg(0))
	index := uint32(ctx.Arg(1))
	_ = ctx.Arg(2) // KeyValueInformationClass
	buffer := ctx.Arg(3)

	rk := ctx.Handles.GetRegKey(keyHandle)
	if rk == nil {
		return StatusInvalidHandle
	}

	names := ctx.Reg.EnumerateValues(rk.Key)
	if int(index) >= len(names) {
		return StatusNoMoreEntries
	}

	val := rk.Key.Values[names[index]]
	if val == nil {
		return StatusNoMoreEntries
	}

	// KEY_VALUE_BASIC_INFORMATION
	if buffer != 0 {
		nameUTF16 := encodeUTF16LE(val.Name)
		ctx.Mem.Write32(buffer+0, 0)                       // TitleIndex
		ctx.Mem.Write32(buffer+4, val.Type)                 // Type
		ctx.Mem.Write32(buffer+8, uint32(len(nameUTF16)))   // NameLength
		ctx.Mem.WriteBytes(buffer+12, nameUTF16)
	}

	return StatusSuccess
}

func handleNtQueryKey(ctx *TrapContext) uint32 {
	return StatusSuccess
}

// ======================== PROCESS / THREAD ========================

func handleNtQueryInformationProcess(ctx *TrapContext) uint32 {
	// ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength
	_ = ctx.Arg(0) // handle (-1 = current process)
	infoClass := uint32(ctx.Arg(1))
	buffer := ctx.Arg(2)
	_ = ctx.Arg(3) // length

	switch infoClass {
	case 0: // ProcessBasicInformation
		if buffer != 0 {
			ctx.Mem.Write32(buffer+0, 0)           // ExitStatus
			ctx.Mem.Write64(buffer+8, ctx.State.PEBAddr) // PebBaseAddress
			ctx.Mem.Write64(buffer+16, 0)          // AffinityMask
			ctx.Mem.Write32(buffer+24, 0)          // BasePriority
			ctx.Mem.Write64(buffer+28, uint64(ctx.State.TEBAddr)) // UniqueProcessId
			ctx.Mem.Write64(buffer+36, 0)          // InheritedFromUniqueProcessId
		}
	case 36: // ProcessImageFileName
		if buffer != 0 {
			imgPath := `\Device\HarddiskVolume1\program.exe`
			utf16 := encodeUTF16LE(imgPath)
			// UNICODE_STRING
			ctx.Mem.Write16(buffer+0, uint16(len(utf16)))
			ctx.Mem.Write16(buffer+2, uint16(len(utf16)+2))
			ctx.Mem.Write64(buffer+8, buffer+16)
			ctx.Mem.WriteBytes(buffer+16, utf16)
		}
	default:
		return StatusNotImplemented
	}

	return StatusSuccess
}

func handleNtQueryInformationThread(ctx *TrapContext) uint32 {
	return StatusSuccess // stub
}

func handleNtQuerySystemInformation(ctx *TrapContext) uint32 {
	infoClass := uint32(ctx.Arg(0))
	buffer := ctx.Arg(1)
	_ = ctx.Arg(2) // length

	switch infoClass {
	case 0: // SystemBasicInformation
		if buffer != 0 {
			ctx.Mem.Write32(buffer+0, 0)           // Reserved
			ctx.Mem.Write32(buffer+4, 100)         // TimerResolution
			ctx.Mem.Write32(buffer+8, uint32(mmu.PageSize)) // PageSize
			ctx.Mem.Write32(buffer+12, 262144)     // NumberOfPhysicalPages
			ctx.Mem.Write32(buffer+16, 256)        // LowestPhysicalPageNumber
			ctx.Mem.Write32(buffer+20, 262144)     // HighestPhysicalPageNumber
			ctx.Mem.Write32(buffer+24, uint32(mmu.PageSize)) // AllocationGranularity
			ctx.Mem.Write64(buffer+28, 0x10000)    // MinimumUserModeAddress
			ctx.Mem.Write64(buffer+36, 0x7FFFFFFEFFFF) // MaximumUserModeAddress
			ctx.Mem.Write64(buffer+44, 0xF)        // ActiveProcessorsAffinityMask
			ctx.Mem.Write8(buffer+52, uint8(runtime.NumCPU())) // NumberOfProcessors
		}
	case 1: // SystemProcessorInformation
		if buffer != 0 {
			ctx.Mem.Write16(buffer+0, 9)  // ProcessorArchitecture = AMD64
			ctx.Mem.Write16(buffer+2, 0)  // ProcessorLevel
			ctx.Mem.Write16(buffer+4, 0)  // ProcessorRevision
		}
	default:
		return StatusNotImplemented
	}

	return StatusSuccess
}

func handleNtTerminateProcess(ctx *TrapContext) uint32 {
	exitCode := ctx.Arg(1)
	if ctx.Trace {
		fmt.Printf("  NtTerminateProcess: exitCode=%d\n", exitCode)
	}
	// Signal the CPU to stop
	ctx.CPU.Stop()
	return StatusSuccess
}

// ======================== VIRTUAL MEMORY ========================

func handleNtAllocateVirtualMemory(ctx *TrapContext) uint32 {
	// ProcessHandle, BaseAddress*, ZeroBits, RegionSize*, AllocationType, Protect
	basePtr := ctx.Arg(1)
	sizePtr := ctx.Arg(3)

	baseAddr, _ := ctx.Mem.Read64(basePtr)
	size, _ := ctx.Mem.Read64(sizePtr)

	if size == 0 {
		return StatusInvalidParameter
	}

	// Align size to page boundary
	size = (size + mmu.PageSize - 1) & mmu.PageMask

	perms := mmu.PermRead | mmu.PermWrite
	addr := ctx.Mem.Mmap(baseAddr, size, perms)

	ctx.Mem.Write64(basePtr, addr)
	ctx.Mem.Write64(sizePtr, size)

	return StatusSuccess
}

func handleNtFreeVirtualMemory(ctx *TrapContext) uint32 {
	basePtr := ctx.Arg(1)
	sizePtr := ctx.Arg(3)

	baseAddr, _ := ctx.Mem.Read64(basePtr)
	size, _ := ctx.Mem.Read64(sizePtr)

	if size == 0 {
		size = mmu.PageSize
	}

	ctx.Mem.Munmap(baseAddr, size)
	return StatusSuccess
}

func handleNtProtectVirtualMemory(ctx *TrapContext) uint32 {
	basePtr := ctx.Arg(1)
	sizePtr := ctx.Arg(3)

	baseAddr, _ := ctx.Mem.Read64(basePtr)
	size, _ := ctx.Mem.Read64(sizePtr)

	perms := mmu.PermRead | mmu.PermWrite | mmu.PermExecute
	ctx.Mem.Mprotect(baseAddr, size, perms)

	return StatusSuccess
}

func handleNtQueryVirtualMemory(ctx *TrapContext) uint32 {
	buffer := ctx.Arg(2)
	if buffer != 0 {
		// MEMORY_BASIC_INFORMATION
		ctx.Mem.Write64(buffer+0, 0)          // BaseAddress
		ctx.Mem.Write64(buffer+8, 0)          // AllocationBase
		ctx.Mem.Write32(buffer+16, 0x04)      // AllocationProtect = PAGE_READWRITE
		ctx.Mem.Write64(buffer+24, mmu.PageSize) // RegionSize
		ctx.Mem.Write32(buffer+32, 0x1000)    // State = MEM_COMMIT
		ctx.Mem.Write32(buffer+36, 0x04)      // Protect = PAGE_READWRITE
		ctx.Mem.Write32(buffer+40, 0x20000)   // Type = MEM_PRIVATE
	}
	return StatusSuccess
}

// ======================== SYNCHRONIZATION ========================

func handleNtCreateEvent(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	_ = ctx.Arg(2) // ObjectAttributes
	eventType := ctx.Arg(3)

	autoReset := eventType == 1 // SynchronizationEvent

	evt := &EventHandle{
		autoReset: autoReset,
		signaled:  false,
		waiters:   make(chan struct{}, 64),
	}

	h := ctx.Handles.Alloc(evt)
	ctx.Mem.Write64(handlePtr, uint64(h))
	return StatusSuccess
}

func handleNtSetEvent(ctx *TrapContext) uint32 {
	handle := Handle(ctx.Arg(0))
	evt := ctx.Handles.GetEvent(handle)
	if evt == nil {
		return StatusInvalidHandle
	}

	evt.mu.Lock()
	evt.signaled = true
	evt.mu.Unlock()

	// Wake one waiter
	select {
	case evt.waiters <- struct{}{}:
	default:
	}

	return StatusSuccess
}

func handleNtResetEvent(ctx *TrapContext) uint32 {
	handle := Handle(ctx.Arg(0))
	evt := ctx.Handles.GetEvent(handle)
	if evt == nil {
		return StatusInvalidHandle
	}

	evt.mu.Lock()
	evt.signaled = false
	evt.mu.Unlock()

	return StatusSuccess
}

func handleNtClearEvent(ctx *TrapContext) uint32 {
	return handleNtResetEvent(ctx)
}

func handleNtWaitForSingleObject(ctx *TrapContext) uint32 {
	handle := Handle(ctx.Arg(0))
	_ = ctx.Arg(1) // Alertable
	timeoutPtr := ctx.Arg(2)

	evt := ctx.Handles.GetEvent(handle)
	if evt == nil {
		return StatusInvalidHandle
	}

	// Check if already signaled
	evt.mu.Lock()
	if evt.signaled {
		if evt.autoReset {
			evt.signaled = false
		}
		evt.mu.Unlock()
		return StatusWait0
	}
	evt.mu.Unlock()

	// Wait with optional timeout
	var timeout time.Duration
	if timeoutPtr != 0 {
		t, _ := ctx.Mem.Read64(timeoutPtr)
		// NT uses 100ns intervals, negative = relative
		if int64(t) < 0 {
			timeout = time.Duration(-int64(t)) * 100
		} else {
			timeout = 1 * time.Second // default
		}
	} else {
		timeout = 30 * time.Second // max wait
	}

	select {
	case <-evt.waiters:
		return StatusWait0
	case <-time.After(timeout):
		return StatusTimeout
	}
}

func handleNtWaitForMultipleObjects(ctx *TrapContext) uint32 {
	// Simplified: wait for first object
	return StatusWait0
}

func handleNtCreateMutant(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	m := &MutantHandle{}
	h := ctx.Handles.Alloc(m)
	ctx.Mem.Write64(handlePtr, uint64(h))
	return StatusSuccess
}

func handleNtReleaseMutant(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtDelayExecution(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0) // Alertable
	intervalPtr := ctx.Arg(1)

	if intervalPtr != 0 {
		interval, _ := ctx.Mem.Read64(intervalPtr)
		if int64(interval) < 0 {
			dur := time.Duration(-int64(interval)) * 100
			time.Sleep(dur)
		}
	}
	return StatusSuccess
}

func handleNtYieldExecution(ctx *TrapContext) uint32 {
	runtime.Gosched()
	return StatusSuccess
}

func handleNtQueryPerformanceCounter(ctx *TrapContext) uint32 {
	counterPtr := ctx.Arg(0)
	freqPtr := ctx.Arg(1)

	now := time.Now().UnixNano()
	if counterPtr != 0 {
		ctx.Mem.Write64(counterPtr, uint64(now/100)) // 100ns intervals
	}
	if freqPtr != 0 {
		ctx.Mem.Write64(freqPtr, 10000000) // 10 MHz
	}
	return StatusSuccess
}

func handleNtQuerySystemTime(ctx *TrapContext) uint32 {
	timePtr := ctx.Arg(0)
	if timePtr != 0 {
		// Windows FILETIME: 100ns intervals since Jan 1, 1601
		// Epoch offset: 11644473600 seconds
		now := time.Now()
		ft := (now.Unix()+11644473600)*10000000 + int64(now.Nanosecond()/100)
		ctx.Mem.Write64(timePtr, uint64(ft))
	}
	return StatusSuccess
}

// ======================== CRITICAL SECTIONS ========================

func handleRtlInitCritSec(ctx *TrapContext) uint32 {
	// Just zero-init the RTL_CRITICAL_SECTION structure in guest memory
	csAddr := ctx.Arg(0)
	if csAddr != 0 {
		// DebugInfo(8) + LockCount(-1=4) + RecursionCount(4) + OwningThread(8) + LockSemaphore(8) + SpinCount(8)
		ctx.Mem.Write64(csAddr+0, 0)            // DebugInfo
		ctx.Mem.Write32(csAddr+8, 0xFFFFFFFF)   // LockCount = -1 (unlocked)
		ctx.Mem.Write32(csAddr+12, 0)           // RecursionCount
		ctx.Mem.Write64(csAddr+16, 0)           // OwningThread
		ctx.Mem.Write64(csAddr+24, 0)           // LockSemaphore
		ctx.Mem.Write64(csAddr+32, 0)           // SpinCount
	}
	return StatusSuccess
}

func handleRtlEnterCritSec(ctx *TrapContext) uint32 {
	// Simplified: just set the lock count to 0 (locked)
	csAddr := ctx.Arg(0)
	if csAddr != 0 {
		ctx.Mem.Write32(csAddr+8, 0)  // LockCount = 0
		ctx.Mem.Write32(csAddr+12, 1) // RecursionCount = 1
	}
	return StatusSuccess
}

func handleRtlLeaveCritSec(ctx *TrapContext) uint32 {
	csAddr := ctx.Arg(0)
	if csAddr != 0 {
		ctx.Mem.Write32(csAddr+8, 0xFFFFFFFF) // LockCount = -1
		ctx.Mem.Write32(csAddr+12, 0)         // RecursionCount = 0
	}
	return StatusSuccess
}

func handleRtlDeleteCritSec(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlTryEnterCritSec(ctx *TrapContext) uint32 {
	// Always succeed
	handleRtlEnterCritSec(ctx)
	// Return TRUE (1) for success
	ctx.CPU.SetSyscallReturn(1)
	return 1 // TRUE
}

// ======================== SRW LOCKS ========================

func handleRtlInitSRWLock(ctx *TrapContext) uint32 {
	addr := ctx.Arg(0)
	if addr != 0 {
		ctx.Mem.Write64(addr, 0)
	}
	return StatusSuccess
}

func handleRtlAcquireSRWExcl(ctx *TrapContext) uint32  { return StatusSuccess }
func handleRtlReleaseSRWExcl(ctx *TrapContext) uint32  { return StatusSuccess }
func handleRtlAcquireSRWShared(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlReleaseSRWShared(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlTryAcquireSRWExcl(ctx *TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1)
	return 1
}
func handleRtlTryAcquireSRWShared(ctx *TrapContext) uint32 {
	ctx.CPU.SetSyscallReturn(1)
	return 1
}

// ======================== CONDITION VARIABLES ========================

func handleRtlInitCondVar(ctx *TrapContext) uint32 {
	addr := ctx.Arg(0)
	if addr != 0 {
		ctx.Mem.Write64(addr, 0)
	}
	return StatusSuccess
}
func handleRtlWakeCondVar(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlWakeAllCondVar(ctx *TrapContext) uint32 { return StatusSuccess }

// ======================== HEAP ========================

func handleRtlCreateHeap(ctx *TrapContext) uint32 {
	heap := &HeapHandle{
		Allocations: make(map[uint64]uint64),
	}
	h := ctx.Handles.Alloc(heap)
	ctx.CPU.SetSyscallReturn(uint64(h))
	return uint32(h) // return heap handle as PVOID
}

func handleRtlDestroyHeap(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlAllocateHeap(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0)  // HeapHandle
	_ = ctx.Arg(1)  // Flags
	size := ctx.Arg(2)

	if size == 0 {
		size = 16
	}

	addr := ctx.Mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
	ctx.CPU.SetSyscallReturn(addr)
	return uint32(addr) // return pointer, not NTSTATUS
}

func handleRtlFreeHeap(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0) // HeapHandle
	_ = ctx.Arg(1) // Flags
	addr := ctx.Arg(2)

	if addr != 0 {
		ctx.Mem.Munmap(addr, mmu.PageSize)
	}
	ctx.CPU.SetSyscallReturn(1) // TRUE
	return 1
}

func handleRtlReAllocateHeap(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0)     // HeapHandle
	_ = ctx.Arg(1)     // Flags
	oldAddr := ctx.Arg(2)
	newSize := ctx.Arg(3)

	if newSize == 0 {
		newSize = 16
	}

	newAddr := ctx.Mem.Mmap(0, newSize, mmu.PermRead|mmu.PermWrite)

	// Copy old data (best effort)
	if oldAddr != 0 {
		oldData, err := ctx.Mem.ReadBytes(oldAddr, int(newSize))
		if err == nil {
			ctx.Mem.WriteBytes(newAddr, oldData)
		}
	}

	ctx.CPU.SetSyscallReturn(newAddr)
	return uint32(newAddr)
}

func handleRtlSizeHeap(ctx *TrapContext) uint32 {
	// Return a dummy size
	ctx.CPU.SetSyscallReturn(mmu.PageSize)
	return uint32(mmu.PageSize)
}

// ======================== STRING / UNICODE ========================

func handleRtlInitUnicodeString(ctx *TrapContext) uint32 {
	destAddr := ctx.Arg(0) // PUNICODE_STRING
	srcAddr := ctx.Arg(1)  // PCWSTR

	if destAddr == 0 {
		return StatusSuccess
	}

	if srcAddr == 0 {
		ctx.Mem.Write16(destAddr+0, 0) // Length
		ctx.Mem.Write16(destAddr+2, 0) // MaximumLength
		ctx.Mem.Write64(destAddr+8, 0) // Buffer
		return StatusSuccess
	}

	// Find length of UTF-16 string
	length := uint16(0)
	for i := uint64(0); i < 65536; i += 2 {
		ch, err := ctx.Mem.Read16(srcAddr + i)
		if err != nil || ch == 0 {
			break
		}
		length += 2
	}

	ctx.Mem.Write16(destAddr+0, length)        // Length (bytes, not including null)
	ctx.Mem.Write16(destAddr+2, length+2)      // MaximumLength
	ctx.Mem.Write64(destAddr+8, srcAddr)       // Buffer
	return StatusSuccess
}

// ======================== MISC ========================

func handleRtlGetVersion(ctx *TrapContext) uint32 {
	buffer := ctx.Arg(0) // PRTL_OSVERSIONINFOW

	if buffer != 0 {
		// dwOSVersionInfoSize
		ctx.Mem.Write32(buffer+0, 284)  // sizeof(RTL_OSVERSIONINFOW)
		ctx.Mem.Write32(buffer+4, 10)   // dwMajorVersion
		ctx.Mem.Write32(buffer+8, 0)    // dwMinorVersion
		ctx.Mem.Write32(buffer+12, 19045) // dwBuildNumber
		ctx.Mem.Write32(buffer+16, 2)   // dwPlatformId = VER_PLATFORM_WIN32_NT
	}
	return StatusSuccess
}

func handleRtlNtStatusToDosError(ctx *TrapContext) uint32 {
	status := uint32(ctx.Arg(0))
	var dosError uint32

	switch status {
	case StatusSuccess:
		dosError = 0 // ERROR_SUCCESS
	case StatusNoSuchFile, StatusObjectNameNotFound:
		dosError = 2 // ERROR_FILE_NOT_FOUND
	case StatusObjectPathNotFound:
		dosError = 3 // ERROR_PATH_NOT_FOUND
	case StatusAccessDenied:
		dosError = 5 // ERROR_ACCESS_DENIED
	case StatusInvalidHandle:
		dosError = 6 // ERROR_INVALID_HANDLE
	case StatusNoMemory:
		dosError = 8 // ERROR_NOT_ENOUGH_MEMORY
	case StatusInvalidParameter:
		dosError = 87 // ERROR_INVALID_PARAMETER
	default:
		dosError = 317 // ERROR_MR_MID_NOT_FOUND
	}

	ctx.CPU.SetSyscallReturn(uint64(dosError))
	return dosError
}

func handleRtlSetLastWin32Error(ctx *TrapContext) uint32 {
	errorCode := uint32(ctx.Arg(0))
	// Write to TEB.LastErrorValue
	if ctx.State != nil && ctx.State.TEBAddr != 0 {
		ctx.Mem.Write32(ctx.State.TEBAddr+TebLastErrorValue, errorCode)
	}
	return StatusSuccess
}

func handleRtlGetLastWin32Error(ctx *TrapContext) uint32 {
	if ctx.State != nil && ctx.State.TEBAddr != 0 {
		val, err := ctx.Mem.Read32(ctx.State.TEBAddr + TebLastErrorValue)
		if err == nil {
			ctx.CPU.SetSyscallReturn(uint64(val))
			return val
		}
	}
	return 0
}

func handleNtDuplicateObject(ctx *TrapContext) uint32 {
	srcHandle := Handle(ctx.Arg(2))
	targetHandlePtr := ctx.Arg(3)

	obj := ctx.Handles.Get(srcHandle)
	if obj == nil {
		return StatusInvalidHandle
	}

	newHandle := ctx.Handles.Alloc(obj)
	if targetHandlePtr != 0 {
		ctx.Mem.Write64(targetHandlePtr, uint64(newHandle))
	}
	return StatusSuccess
}

func handleNtQueryObject(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

// ======================== LDR (DLL LOADING) ========================

func handleLdrGetDllHandle(ctx *TrapContext) uint32 {
	// LdrGetDllHandle(PathToFile, Unused, ModuleName*, ModuleHandle*)
	return StatusNotImplemented
}

func handleLdrGetProcedureAddress(ctx *TrapContext) uint32 {
	// LdrGetProcedureAddress(ModuleHandle, FunctionName*, Ordinal, FunctionAddress*)
	return StatusNotImplemented
}

// ======================== Helpers ========================

// writeIOStatus writes an IO_STATUS_BLOCK.
func writeIOStatus(mem *mmu.MMU, addr uint64, status uint32, info uint64) {
	if addr == 0 {
		return
	}
	mem.Write32(addr, status)
	mem.Write64(addr+8, info)
}

// windowsFileTime converts a time.Time to Windows FILETIME (100ns since 1601-01-01).
func windowsFileTime(t time.Time) uint64 {
	const epochDiff = 11644473600
	return uint64((t.Unix()+epochDiff)*10000000 + int64(t.Nanosecond()/100))
}

// readGuestStringUTF16 reads a null-terminated UTF-16LE string from guest memory.
func readGuestStringUTF16(mem *mmu.MMU, addr uint64, maxBytes int) string {
	if addr == 0 {
		return ""
	}
	data, err := mem.ReadBytes(addr, maxBytes)
	if err != nil {
		return ""
	}
	return decodeUTF16LE(data)
}

// writeGuestUTF16 writes a string as UTF-16LE with null terminator to guest memory.
func writeGuestUTF16(mem *mmu.MMU, addr uint64, s string) int {
	utf16 := encodeUTF16LE(s)
	data := append(utf16, 0, 0)
	mem.WriteBytes(addr, data)
	return len(data)
}

// encode32LE encodes a uint32 as little-endian bytes.
func encode32LE(val uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, val)
	return b
}

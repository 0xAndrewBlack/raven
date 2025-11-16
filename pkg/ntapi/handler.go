package ntapi

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
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
	// ReactOS reference: ntoskrnl/io/iomgr/iofunc.c NtReadFile
	fileHandle := Handle(ctx.Arg(0))
	eventHandle := Handle(ctx.Arg(1))
	// Arg(2) = ApcRoutine (ignored)
	// Arg(3) = ApcContext (ignored)
	ioStatus := ctx.Arg(4)
	bufAddr  := ctx.Arg(5)
	length   := ctx.Arg(6)
	pByteOffset := ctx.Arg(7)
	// Arg(8) = Key (ignored)

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		return StatusInvalidHandle
	}

	// Seek if ByteOffset provided and not special sentinel (0x8000000000000000 = use current pos)
	if pByteOffset != 0 {
		offset, _ := ctx.Mem.Read64(pByteOffset)
		if offset != 0x8000000000000000 && offset != 0xFFFFFFFFFFFFFFFF {
			buf := make([]byte, length)
			n, err := ctx.FS.Pread(fh.FD, buf, int64(offset))
			status := uint32(StatusSuccess)
			if n == 0 && err != nil {
				status = 0xC0000011 // STATUS_END_OF_FILE
			}
			if n > 0 {
				ctx.Mem.WriteBytes(bufAddr, buf[:n])
			}
			if ioStatus != 0 {
				ctx.Mem.Write64(ioStatus, uint64(status))
				ctx.Mem.Write64(ioStatus+8, uint64(n))
			}
			if eventHandle != 0 {
				if eh := ctx.Handles.GetEvent(eventHandle); eh != nil {
					eh.Set()
				}
			}
			return status
		}
	}

	buf := make([]byte, length)
	n, err := ctx.FS.Read(fh.FD, buf)
	status := uint32(StatusSuccess)
	if n == 0 && err != nil {
		status = 0xC0000011 // STATUS_END_OF_FILE
	}

	if n > 0 {
		ctx.Mem.WriteBytes(bufAddr, buf[:n])
	}

	if ioStatus != 0 {
		ctx.Mem.Write64(ioStatus, uint64(status))
		ctx.Mem.Write64(ioStatus+8, uint64(n))
	}

	// Signal event handle if provided
	if eventHandle != 0 {
		if eh := ctx.Handles.GetEvent(eventHandle); eh != nil {
			eh.Set()
		}
	}

	return status
}

func handleNtWriteFile(ctx *TrapContext) uint32 {
	// NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock*, Buffer, Length, ByteOffset*, Key*)
	// ReactOS reference: ntoskrnl/io/iomgr/iofunc.c NtWriteFile
	fileHandle := Handle(ctx.Arg(0))
	eventHandle := Handle(ctx.Arg(1))
	// Arg(2) = ApcRoutine (ignored)
	// Arg(3) = ApcContext (ignored)
	ioStatus    := ctx.Arg(4)
	bufAddr     := ctx.Arg(5)
	length      := ctx.Arg(6)
	pByteOffset := ctx.Arg(7)
	// Arg(8) = Key (ignored)

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
			ctx.Mem.Write64(ioStatus, uint64(StatusSuccess))
			ctx.Mem.Write64(ioStatus+8, length)
		}
		return StatusSuccess
	}

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		return StatusInvalidHandle
	}

	// Seek if ByteOffset provided
	if pByteOffset != 0 {
		offset, _ := ctx.Mem.Read64(pByteOffset)
		if offset != 0x8000000000000000 && offset != 0xFFFFFFFFFFFFFFFF {
			data, err := ctx.Mem.ReadBytes(bufAddr, int(length))
			if err != nil {
				return StatusInvalidParameter
			}
			n, writeErr := ctx.FS.Pwrite(fh.FD, data, int64(offset))
			if writeErr != nil {
				return StatusAccessDenied
			}
			if ioStatus != 0 {
				ctx.Mem.Write64(ioStatus, uint64(StatusSuccess))
				ctx.Mem.Write64(ioStatus+8, uint64(n))
			}
			if eventHandle != 0 {
				if eh := ctx.Handles.GetEvent(eventHandle); eh != nil {
					eh.Set()
				}
			}
			return StatusSuccess
		}
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
		ctx.Mem.Write64(ioStatus, uint64(StatusSuccess))
		ctx.Mem.Write64(ioStatus+8, uint64(n))
	}

	// Signal event handle if provided
	if eventHandle != 0 {
		if eh := ctx.Handles.GetEvent(eventHandle); eh != nil {
			eh.Set()
		}
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

func handleNtDeviceIoControlFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	_ = ctx.Arg(1)  // Event
	_ = ctx.Arg(2)  // ApcRoutine
	_ = ctx.Arg(3)  // ApcContext
	ioStatus := ctx.Arg(4)
	ioctlCode := uint32(ctx.Arg(5))

	if ctx.Trace {
		fmt.Printf("  NtDeviceIoControlFile: handle=0x%x ioctl=0x%08x\n", fileHandle, ioctlCode)
	}

	// Decode device type from IOCTL code
	deviceType := (ioctlCode >> 16) & 0xFFFF

	// Console device IOCTLs (FILE_DEVICE_CONSOLE = 0x50) - succeed silently
	// even for invalid handles, as Wine uses these for debug output via condrv
	if deviceType == 0x50 {
		if ctx.Trace {
			inputBuf := ctx.Arg(6)
			inputLen := uint32(ctx.Arg(7)) // ULONG - 32-bit
			if inputBuf != 0 && inputLen > 0 && inputLen < 4096 {
				data, err := ctx.Mem.ReadBytes(inputBuf, int(inputLen))
				if err == nil {
					fmt.Printf("  [wine] %s", string(data))
				}
			}
		}
		if ioStatus != 0 {
			ctx.Mem.Write32(ioStatus, StatusSuccess)
			ctx.Mem.Write64(ioStatus+8, 0)
		}
		return StatusSuccess
	}

	// Reject truly invalid handles for non-console IOCTLs
	if fileHandle == 0xFFFFFFFFFFFFFFFF || fileHandle == 0 {
		if ioStatus != 0 {
			ctx.Mem.Write32(ioStatus, StatusInvalidHandle)
			ctx.Mem.Write64(ioStatus+8, 0)
		}
		return StatusInvalidHandle
	}

	// Console mode IOCTLs (legacy path)
	const (
		ctlCodeGetMode = 0x500000
		ctlCodeSetMode = 0x500004
	)

	switch ioctlCode {
	case ctlCodeGetMode:
		outBuf := ctx.Arg(8)
		if outBuf != 0 {
			ctx.Mem.Write32(outBuf, 0x0007)
		}
	case ctlCodeSetMode:
		// Accept silently
	default:
		// Unknown IOCTL - succeed silently
	}

	if ioStatus != 0 {
		ctx.Mem.Write32(ioStatus, StatusSuccess)
		ctx.Mem.Write64(ioStatus+8, 0)
	}

	return StatusSuccess
}

func handleNtCreateSection(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	_ = ctx.Arg(2) // ObjectAttributes
	maxSizePtr := ctx.Arg(3)

	var maxSize uint64
	if maxSizePtr != 0 {
		maxSize, _ = ctx.Mem.Read64(maxSizePtr)
	}
	if maxSize == 0 {
		maxSize = mmu.PageSize
	}

	sec := &SectionHandle{
		Size:  maxSize,
		Perms: mmu.PermRead | mmu.PermWrite,
	}

	h := ctx.Handles.Alloc(sec)
	ctx.Mem.Write64(handlePtr, uint64(h))

	return StatusSuccess
}

func handleNtMapViewOfSection(ctx *TrapContext) uint32 {
	sectionHandle := Handle(ctx.Arg(0))
	_ = ctx.Arg(1) // ProcessHandle
	baseAddrPtr := ctx.Arg(2)
	_ = ctx.Arg(3) // ZeroBits

	sec := ctx.Handles.GetSection(sectionHandle)
	if sec == nil {
		return StatusInvalidHandle
	}

	size := sec.Size
	if size == 0 {
		size = mmu.PageSize
	}
	size = (size + mmu.PageSize - 1) & mmu.PageMask

	addr := ctx.Mem.Mmap(0, size, sec.Perms)
	if baseAddrPtr != 0 {
		ctx.Mem.Write64(baseAddrPtr, addr)
	}

	return StatusSuccess
}

func handleNtUnmapViewOfSection(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0) // ProcessHandle
	baseAddr := ctx.Arg(1)

	if baseAddr != 0 {
		ctx.Mem.Munmap(baseAddr, mmu.PageSize)
	}
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

	case 2: // SystemProcessorPerformanceInformation (per-cpu array, 48 bytes each)
		if buffer != 0 {
			nCPU := runtime.NumCPU()
			now := uint64(time.Now().UnixNano() / 100)
			for i := 0; i < nCPU; i++ {
				base := buffer + uint64(i)*48
				ctx.Mem.Write64(base+0, 0)    // IdleTime
				ctx.Mem.Write64(base+8, now)   // KernelTime
				ctx.Mem.Write64(base+16, now)  // UserTime
				ctx.Mem.Write64(base+24, 0)    // DpcTime
				ctx.Mem.Write64(base+32, 0)    // InterruptTime
				ctx.Mem.Write32(base+40, 0)    // InterruptCount
			}
		}

	case 3: // SystemTimeOfDayInformation (48 bytes)
		if buffer != 0 {
			now := uint64(time.Now().UnixNano()/100 + 116444736000000000) // NT epoch
			ctx.Mem.Write64(buffer+0, now)  // BootTime
			ctx.Mem.Write64(buffer+8, now)  // CurrentTime
			ctx.Mem.Write64(buffer+16, 0)   // TimeZoneBias
			ctx.Mem.Write32(buffer+24, 0)   // TimeZoneId
			ctx.Mem.Write32(buffer+28, 0)   // Reserved
		}

	case 5: // SystemProcessInformation - minimal single-process entry
		if buffer != 0 {
			// SYSTEM_PROCESS_INFORMATION: NextEntryOffset=0 terminates list
			ctx.Mem.Write32(buffer+0, 0)    // NextEntryOffset (last entry)
			ctx.Mem.Write32(buffer+4, 0)    // NumberOfThreads
			ctx.Mem.Write64(buffer+8, 0)    // WorkingSetPrivateSize
			ctx.Mem.Write32(buffer+16, 0)   // HardFaultCount
			ctx.Mem.Write32(buffer+36, 0)   // SessionId
			ctx.Mem.Write64(buffer+56, 4)   // UniqueProcessId (PID 4)
			ctx.Mem.Write64(buffer+64, 0)   // InheritedFromUniqueProcessId
			ctx.Mem.Write32(buffer+72, 0)   // HandleCount
		}

	case 7: // SystemProcessorSpeedInformation / SystemNumaProcessorMap
		// success with empty data

	case 8: // SystemProcessorPerformanceInformation (alias for case 2)
		if buffer != 0 {
			nCPU := runtime.NumCPU()
			now := uint64(time.Now().UnixNano() / 100)
			for i := 0; i < nCPU; i++ {
				base := buffer + uint64(i)*48
				ctx.Mem.Write64(base+0, 0)
				ctx.Mem.Write64(base+8, now)
				ctx.Mem.Write64(base+16, now)
				ctx.Mem.Write64(base+24, 0)
				ctx.Mem.Write64(base+32, 0)
				ctx.Mem.Write32(base+40, 0)
			}
		}

	case 11: // SystemModuleInformation (RTL_PROCESS_MODULES)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0) // NumberOfModules = 0
		}

	case 23: // SystemInterruptInformation
		// success with empty data

	case 44: // SystemExtendedHandleInformation
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0)   // NumberOfHandles
			ctx.Mem.Write64(buffer+8, 0) // Reserved
		}

	case 64: // SystemCodeIntegrityInformation
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0)
		}

	case 173: // SystemCodeIntegrityUnlockModeInformation
		// success with empty data

	default:
		// Many apps only check NTSTATUS, not the data - return success.
		if ctx.Trace {
			fmt.Printf("  NtQuerySystemInformation: unhandled class %d\n", infoClass)
		}
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
	if addr < 0x1000 {
		ravelog.Logf("[WARN] NtAllocateVirtualMemory failed addr=0x%x size=0x%x baseAddr=0x%x\n", addr, size, baseAddr)
		return StatusNoMemory
	}

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
	addr := ctx.Arg(1)
	buffer := ctx.Arg(3)
	if buffer == 0 {
		return StatusSuccess
	}

	base, size, mapped, perms := ctx.Mem.QueryRegion(addr)

	// Convert MMU perms to Win32 PAGE_xxx constants.
	var protect uint32
	if !mapped {
		protect = 0x01 // PAGE_NOACCESS
	} else {
		switch {
		case perms&(mmu.PermRead|mmu.PermWrite|mmu.PermExecute) == mmu.PermRead|mmu.PermWrite|mmu.PermExecute:
			protect = 0x40 // PAGE_EXECUTE_READWRITE
		case perms&(mmu.PermRead|mmu.PermExecute) == mmu.PermRead|mmu.PermExecute:
			protect = 0x20 // PAGE_EXECUTE_READ
		case perms&(mmu.PermRead|mmu.PermWrite) == mmu.PermRead|mmu.PermWrite:
			protect = 0x04 // PAGE_READWRITE
		default:
			protect = 0x02 // PAGE_READONLY
		}
	}

	var state, typ uint32
	if mapped {
		state = 0x1000  // MEM_COMMIT
		typ = 0x20000   // MEM_PRIVATE
	} else {
		state = 0x10000 // MEM_FREE
		typ = 0
		protect = 0x01  // PAGE_NOACCESS
	}

	// MEMORY_BASIC_INFORMATION layout (Win64):
	// +0  BaseAddress        (PVOID, 8)
	// +8  AllocationBase     (PVOID, 8)
	// +16 AllocationProtect  (DWORD, 4) + padding (4)
	// +24 RegionSize         (SIZE_T, 8)
	// +32 State              (DWORD, 4)
	// +36 Protect            (DWORD, 4)
	// +40 Type               (DWORD, 4)
	ctx.Mem.Write64(buffer+0, base)
	ctx.Mem.Write64(buffer+8, base) // AllocationBase = BaseAddress (simplified)
	ctx.Mem.Write32(buffer+16, protect)
	ctx.Mem.Write32(buffer+20, 0) // PartitionId padding
	ctx.Mem.Write64(buffer+24, size)
	ctx.Mem.Write32(buffer+32, state)
	ctx.Mem.Write32(buffer+36, protect)
	ctx.Mem.Write32(buffer+40, typ)

	return StatusSuccess
}

// ======================== SYNCHRONIZATION ========================

func handleNtCreateEvent(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	objAttr := ctx.Arg(2)
	eventType := ctx.Arg(3)

	autoReset := eventType == 1 // SynchronizationEvent

	evt := &EventHandle{
		autoReset: autoReset,
		signaled:  false,
	}

	// Read name from OBJECT_ATTRIBUTES if present
	var name string
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}

	var h Handle
	if name != "" {
		var isNew bool
		h, isNew = ctx.Handles.AllocNamed(name, evt)
		if !isNew {
			// STATUS_OBJECT_NAME_COLLISION is not quite right for NT;
			// the real kernel returns STATUS_OBJECT_NAME_EXISTS (0x40000000)
			ctx.Mem.Write64(handlePtr, uint64(h))
			return 0x40000000 // STATUS_OBJECT_NAME_EXISTS (success with info)
		}
	} else {
		h = ctx.Handles.Alloc(evt)
	}

	ctx.Mem.Write64(handlePtr, uint64(h))
	return StatusSuccess
}

func handleNtSetEvent(ctx *TrapContext) uint32 {
	handle := Handle(ctx.Arg(0))
	evt := ctx.Handles.GetEvent(handle)
	if evt == nil {
		return StatusInvalidHandle
	}

	evt.Set()
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
		timeout = -1 // infinite
	}

	if evt.WaitTimeout(timeout) {
		return StatusWait0
	}
	return StatusTimeout
}

func handleNtWaitForMultipleObjects(ctx *TrapContext) uint32 {
	// NtWaitForMultipleObjects(Count, Handles*, WaitType, Alertable, Timeout*)
	count := uint32(ctx.Arg(0))
	handlesPtr := ctx.Arg(1)
	_ = ctx.Arg(2) // WaitType: 0=WaitAll, 1=WaitAny
	_ = ctx.Arg(3) // Alertable
	timeoutPtr := ctx.Arg(4)

	if count == 0 || handlesPtr == 0 {
		return StatusWait0
	}
	if count > 64 {
		count = 64 // MAXIMUM_WAIT_OBJECTS
	}

	var timeout time.Duration
	if timeoutPtr != 0 {
		t, _ := ctx.Mem.Read64(timeoutPtr)
		if int64(t) < 0 {
			timeout = time.Duration(-int64(t)) * 100
		} else {
			timeout = 1 * time.Second
		}
	} else {
		timeout = -1 // infinite
	}

	// Try each handle in order (simplified WaitAny)
	for i := uint32(0); i < count; i++ {
		hVal, _ := ctx.Mem.Read64(handlesPtr + uint64(i)*8)
		h := Handle(hVal)

		if evt := ctx.Handles.GetEvent(h); evt != nil {
			if evt.WaitTimeout(timeout) {
				return StatusWait0 + uint32(i)
			}
		} else if mh := ctx.Handles.GetMutant(h); mh != nil {
			res := mh.WaitTimeout(1, timeout)
			if res == 0 || res == 0x80 { // WAIT_OBJECT_0 or WAIT_ABANDONED
				return StatusWait0 + uint32(i)
			}
		} else if sh := ctx.Handles.GetSemaphore(h); sh != nil {
			res := sh.WaitTimeout(timeout)
			if res == 0 {
				return StatusWait0 + uint32(i)
			}
		} else if th := ctx.Handles.GetThread(h); th != nil {
			if th.Done != nil {
				if timeout < 0 {
					<-th.Done
				} else {
					select {
					case <-th.Done:
					case <-time.After(timeout):
						continue
					}
				}
				return StatusWait0 + uint32(i)
			}
		}
	}
	return StatusTimeout
}

func handleNtCreateMutant(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	objAttr := ctx.Arg(2)
	initialOwner := ctx.Arg(3) != 0

	m := &MutantHandle{}
	if initialOwner {
		m.WaitTimeout(1, 0) // TID=1 as simplified owner
	}

	var name string
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}

	var h Handle
	if name != "" {
		var isNew bool
		h, isNew = ctx.Handles.AllocNamed(name, m)
		if !isNew {
			ctx.Mem.Write64(handlePtr, uint64(h))
			return 0x40000000 // STATUS_OBJECT_NAME_EXISTS
		}
	} else {
		h = ctx.Handles.Alloc(m)
	}

	ctx.Mem.Write64(handlePtr, uint64(h))
	return StatusSuccess
}

func handleNtReleaseMutant(ctx *TrapContext) uint32 {
	h := Handle(ctx.Arg(0))
	pPrevCount := ctx.Arg(1)
	if mh := ctx.Handles.GetMutant(h); mh != nil {
		mh.mu.Lock()
		prev := mh.count
		mh.mu.Unlock()
		mh.Release(1) // TID=1 simplified
		if pPrevCount != 0 {
			ctx.Mem.Write32(pPrevCount, uint32(prev))
		}
	}
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
	csAddr := ctx.Arg(0)
	if csAddr != 0 {
		// Allocate RTL_CRITICAL_SECTION_DEBUG structure (48 bytes)
		dbgInfo := ctx.Mem.Mmap(0, 48, mmu.PermRead|mmu.PermWrite)
		// DebugInfo: Type=0, CreatorBackTraceIndex=0, CriticalSection pointer at +8
		ctx.Mem.Write64(dbgInfo+8, csAddr) // CriticalSection pointer
		// ProcessLocksList (+16): point to self (empty list)
		ctx.Mem.Write64(dbgInfo+16, dbgInfo+16) // Flink = &self
		ctx.Mem.Write64(dbgInfo+24, dbgInfo+16) // Blink = &self

		// Initialize CRITICAL_SECTION
		ctx.Mem.Write64(csAddr+0, dbgInfo)      // DebugInfo pointer
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
func handleRtlWakeCondVar(ctx *TrapContext) uint32 {
	GlobalCondVars.Get(ctx.Arg(0)).Signal()
	return StatusSuccess
}
func handleRtlWakeAllCondVar(ctx *TrapContext) uint32 {
	GlobalCondVars.Get(ctx.Arg(0)).Broadcast()
	return StatusSuccess
}

// ======================== HEAP ========================

func handleRtlCreateHeap(ctx *TrapContext) uint32 {
	heap := &HeapHandle{
		Allocations: make(map[uint64]uint64),
	}
	h := ctx.Handles.Alloc(heap)
	ctx.CPU.SetSyscallReturn(uint64(h))
	ctx.ReturnOverridden = true
	return 0
}

func handleRtlDestroyHeap(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlAllocateHeap(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0) // HeapHandle
	flags := ctx.Arg(1)
	size := ctx.Arg(2)

	if size == 0 {
		size = 16
	}

	var addr uint64
	if ctx.State != nil && ctx.State.HeapAlloc != nil {
		zeroInit := flags&0x08 != 0 // HEAP_ZERO_MEMORY
		addr = ctx.State.HeapAlloc(size, zeroInit)
	} else {
		addr = ctx.Mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
	}
	ctx.CPU.SetSyscallReturn(addr)
	ctx.ReturnOverridden = true
	return 0
}

func handleRtlFreeHeap(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0) // HeapHandle
	_ = ctx.Arg(1) // Flags
	addr := ctx.Arg(2)

	if addr != 0 {
		if ctx.State != nil && ctx.State.HeapFree != nil {
			ctx.State.HeapFree(addr)
		} else {
			ctx.Mem.Munmap(addr, mmu.PageSize)
		}
	}
	ctx.CPU.SetSyscallReturn(1) // TRUE
	ctx.ReturnOverridden = true
	return 0
}

func handleRtlReAllocateHeap(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0)     // HeapHandle
	flags := ctx.Arg(1)
	oldAddr := ctx.Arg(2)
	newSize := ctx.Arg(3)

	if newSize == 0 {
		newSize = 16
	}

	var newAddr uint64
	if ctx.State != nil && ctx.State.HeapAlloc != nil {
		zeroInit := flags&0x08 != 0 // HEAP_ZERO_MEMORY
		newAddr = ctx.State.HeapAlloc(newSize, zeroInit)
	} else {
		newAddr = ctx.Mem.Mmap(0, newSize, mmu.PermRead|mmu.PermWrite)
	}

	// Copy old data (best effort)
	if oldAddr != 0 && newAddr != 0 {
		copyLen := newSize
		if ctx.State != nil && ctx.State.HeapSize != nil {
			if old := ctx.State.HeapSize(oldAddr); old < copyLen {
				copyLen = old
			}
		}
		oldData, err := ctx.Mem.ReadBytes(oldAddr, int(copyLen))
		if err == nil {
			ctx.Mem.WriteBytes(newAddr, oldData)
		}
		if ctx.State != nil && ctx.State.HeapFree != nil {
			ctx.State.HeapFree(oldAddr)
		}
	}

	ctx.CPU.SetSyscallReturn(newAddr)
	ctx.ReturnOverridden = true
	return 0
}

func handleRtlSizeHeap(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0) // HeapHandle
	_ = ctx.Arg(1) // Flags
	ptr := ctx.Arg(2)

	var sz uint64
	if ctx.State != nil && ctx.State.HeapSize != nil && ptr != 0 {
		sz = ctx.State.HeapSize(ptr)
	} else {
		sz = mmu.PageSize
	}
	ctx.CPU.SetSyscallReturn(sz)
	ctx.ReturnOverridden = true
	return 0
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
		// SXS/activation-context errors → ERROR_SXS_KEY_NOT_FOUND (14007)
		if status >= 0xC0150000 && status <= 0xC015FFFF {
			dosError = 14007
		} else {
			dosError = 317 // ERROR_MR_MID_NOT_FOUND
		}
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
	// ModuleName is UNICODE_STRING*, ModuleHandle is HMODULE*
	moduleNamePtr := ctx.Arg(2) // UNICODE_STRING*
	handlePtr := ctx.Arg(3)     // HMODULE*

	if moduleNamePtr == 0 || handlePtr == 0 {
		return StatusNotImplemented
	}

	nameStr := readGuestUnicodeString(ctx.Mem, moduleNamePtr)
	nameStr = strings.ToLower(nameStr)
	// Strip path, keep only filename
	if idx := strings.LastIndexAny(nameStr, "\\/"); idx >= 0 {
		nameStr = nameStr[idx+1:]
	}
	if !strings.HasSuffix(nameStr, ".dll") {
		nameStr += ".dll"
	}

	base := findModuleByName(ctx, nameStr)
	if base == 0 {
		ctx.Mem.Write64(handlePtr, 0)
		return 0xC0000135 // STATUS_DLL_NOT_FOUND
	}
	ctx.Mem.Write64(handlePtr, base)
	return StatusSuccess
}

func handleLdrGetProcedureAddress(ctx *TrapContext) uint32 {
	// LdrGetProcedureAddress(ModuleHandle, FunctionName*, Ordinal, FunctionAddress*)
	moduleHandle := ctx.Arg(0) // HMODULE (base address)
	funcNamePtr := ctx.Arg(1)  // ANSI_STRING*
	ordinal := uint16(ctx.Arg(2))
	funcAddrPtr := ctx.Arg(3) // PVOID*

	if funcAddrPtr != 0 {
		ctx.Mem.Write64(funcAddrPtr, 0) // Clear output on failure
	}

	if moduleHandle == 0 {
		return StatusNotImplemented
	}

	var funcName string
	if funcNamePtr != 0 {
		// ANSI_STRING: Length(2), MaxLength(2), pad(4), Buffer*(8)
		nameLen, _ := ctx.Mem.Read16(funcNamePtr)
		bufPtr, _ := ctx.Mem.Read64(funcNamePtr + 8)
		if bufPtr != 0 && nameLen > 0 {
			buf := make([]byte, nameLen)
			for i := uint16(0); i < nameLen; i++ {
				b, _ := ctx.Mem.Read8(bufPtr + uint64(i))
				buf[i] = b
			}
			funcName = string(buf)
		}
	}

	// Look up in the Dispatcher's synthetic export table
	addr := ctx.Disp.LookupExportByModule(moduleHandle, funcName, ordinal)
	if ctx.Trace {
		fmt.Printf("  LdrGetProcedureAddress: module=0x%x name=%q ordinal=%d → addr=0x%x\n",
			moduleHandle, funcName, ordinal, addr)
	}
	if addr != 0 && funcAddrPtr != 0 {
		ctx.Mem.Write64(funcAddrPtr, addr)
		return StatusSuccess
	}

	return 0xC0000139 // STATUS_ENTRYPOINT_NOT_FOUND
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

// readGuestUnicodeString reads a UNICODE_STRING structure from guest memory.
func readGuestUnicodeString(mem *mmu.MMU, addr uint64) string {
	if addr == 0 {
		return ""
	}
	length, _ := mem.Read16(addr + UnicodeStringLength)
	bufPtr, _ := mem.Read64(addr + UnicodeStringBuffer)
	if bufPtr == 0 || length == 0 {
		return ""
	}
	return readGuestStringUTF16(mem, bufPtr, int(length))
}

// findModuleByName searches PEB_LDR_DATA InLoadOrderModuleList for a DLL by name.
func findModuleByName(ctx *TrapContext, name string) uint64 {
	pebAddr := ctx.State.PEBAddr
	ldrAddr, _ := ctx.Mem.Read64(pebAddr + PebLdr)
	if ldrAddr == 0 {
		return 0
	}
	// InLoadOrderModuleList is a LIST_ENTRY at LdrData + 0x10
	listHead := ldrAddr + LdrInLoadOrderModuleList
	flink, _ := ctx.Mem.Read64(listHead)

	for flink != 0 && flink != listHead {
		// LDR_DATA_TABLE_ENTRY starts at InLoadOrderLinks
		entry := flink
		// BaseDllName is UNICODE_STRING at offset 0x58
		baseName := readGuestUnicodeString(ctx.Mem, entry+LdrEntryBaseDllName)
		if strings.EqualFold(baseName, name) {
			base, _ := ctx.Mem.Read64(entry + LdrEntryDllBase)
			return base
		}
		flink, _ = ctx.Mem.Read64(flink) // next Flink
	}
	return 0
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

// ======================== Additional handlers for Wine DLL init ========================

func handleRtlGetCurrentPeb(ctx *TrapContext) uint32 {
	ctx.SetReturn(ctx.State.PEBAddr)
	return StatusSuccess
}

func handleRtlAcquirePebLock(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlReleasePebLock(ctx *TrapContext) uint32  { return StatusSuccess }

func handleRtlInitAnsiString(ctx *TrapContext) uint32 {
	// RtlInitAnsiString(PANSI_STRING dest, PCSZ source)
	dest := ctx.Arg(0)
	src := ctx.Arg(1)
	if dest == 0 {
		return StatusSuccess
	}
	if src == 0 {
		ctx.Mem.Write16(dest+0, 0) // Length
		ctx.Mem.Write16(dest+2, 0) // MaximumLength
		ctx.Mem.Write64(dest+8, 0) // Buffer
		return StatusSuccess
	}
	// Measure string length
	length := uint16(0)
	for {
		b, err := ctx.Mem.Read8(src + uint64(length))
		if err != nil || b == 0 {
			break
		}
		length++
	}
	ctx.Mem.Write16(dest+0, length)
	ctx.Mem.Write16(dest+2, length+1)
	ctx.Mem.Write64(dest+8, src)
	return StatusSuccess
}

func handleRtlInitUnicodeStringEx(ctx *TrapContext) uint32 {
	// Same as RtlInitUnicodeString but returns NTSTATUS
	handleRtlInitUnicodeString(ctx)
	return StatusSuccess
}

func handleRtlMultiByteToUnicodeN(ctx *TrapContext) uint32 {
	// RtlMultiByteToUnicodeN(wchar* dst, ULONG dstMax, ULONG* resultLen, char* src, ULONG srcLen)
	dst := ctx.Arg(0)
	dstMax := uint32(ctx.Arg(1))
	resultLenPtr := ctx.Arg(2)
	src := ctx.Arg(3)
	srcLen := uint32(ctx.Arg(4))

	written := uint32(0)
	for i := uint32(0); i < srcLen && written+2 <= dstMax; i++ {
		b, err := ctx.Mem.Read8(src + uint64(i))
		if err != nil {
			break
		}
		ctx.Mem.Write16(dst+uint64(written), uint16(b))
		written += 2
	}
	if resultLenPtr != 0 {
		ctx.Mem.Write32(resultLenPtr, written)
	}
	return StatusSuccess
}

func handleRtlMultiByteToUnicodeSize(ctx *TrapContext) uint32 {
	// RtlMultiByteToUnicodeSize(ULONG* resultSize, char* src, ULONG srcLen)
	resultPtr := ctx.Arg(0)
	srcLen := uint32(ctx.Arg(2))
	if resultPtr != 0 {
		ctx.Mem.Write32(resultPtr, srcLen*2)
	}
	return StatusSuccess
}

func handleRtlUnicodeToMultiByteN(ctx *TrapContext) uint32 {
	// RtlUnicodeToMultiByteN(char* dst, ULONG dstMax, ULONG* resultLen, wchar* src, ULONG srcLen)
	dst := ctx.Arg(0)
	dstMax := uint32(ctx.Arg(1))
	resultLenPtr := ctx.Arg(2)
	src := ctx.Arg(3)
	srcLen := uint32(ctx.Arg(4))

	written := uint32(0)
	for i := uint32(0); i+2 <= srcLen && written < dstMax; i += 2 {
		ch, err := ctx.Mem.Read16(src + uint64(i))
		if err != nil {
			break
		}
		if ch > 127 {
			ch = '?'
		}
		ctx.Mem.Write8(dst+uint64(written), uint8(ch))
		written++
	}
	if resultLenPtr != 0 {
		ctx.Mem.Write32(resultLenPtr, written)
	}
	return StatusSuccess
}

func handleRtlUnicodeToMultiByteSize(ctx *TrapContext) uint32 {
	resultPtr := ctx.Arg(0)
	srcLen := uint32(ctx.Arg(2))
	if resultPtr != 0 {
		ctx.Mem.Write32(resultPtr, srcLen/2)
	}
	return StatusSuccess
}

func handleRtlAnsiStringToUnicodeString(ctx *TrapContext) uint32 {
	// RtlAnsiStringToUnicodeString(PUNICODE_STRING dest, PANSI_STRING src, BOOLEAN alloc)
	dest := ctx.Arg(0)
	src := ctx.Arg(1)
	allocate := ctx.Arg(2) != 0

	if dest == 0 || src == 0 {
		return StatusInvalidParameter
	}

	srcLen, _ := ctx.Mem.Read16(src + 0)
	srcBuf, _ := ctx.Mem.Read64(src + 8)
	uniLen := uint16(srcLen) * 2
	uniMaxLen := uniLen + 2

	var uniBuf uint64
	if allocate {
		uniBuf = ctx.Mem.Mmap(0, uint64(uniMaxLen), mmu.PermRead|mmu.PermWrite)
	} else {
		uniBuf, _ = ctx.Mem.Read64(dest + 8)
	}

	for i := uint16(0); i < srcLen; i++ {
		b, _ := ctx.Mem.Read8(srcBuf + uint64(i))
		ctx.Mem.Write16(uniBuf+uint64(i)*2, uint16(b))
	}
	ctx.Mem.Write16(uniBuf+uint64(srcLen)*2, 0) // null terminator

	ctx.Mem.Write16(dest+0, uniLen)
	ctx.Mem.Write16(dest+2, uniMaxLen)
	ctx.Mem.Write64(dest+8, uniBuf)
	return StatusSuccess
}

func handleRtlUnicodeStringToAnsiString(ctx *TrapContext) uint32 {
	dest := ctx.Arg(0)
	src := ctx.Arg(1)
	allocate := ctx.Arg(2) != 0

	if dest == 0 || src == 0 {
		return StatusInvalidParameter
	}

	srcLen, _ := ctx.Mem.Read16(src + 0)
	srcBuf, _ := ctx.Mem.Read64(src + 8)
	ansiLen := srcLen / 2
	ansiMaxLen := ansiLen + 1

	var ansiBuf uint64
	if allocate {
		ansiBuf = ctx.Mem.Mmap(0, uint64(ansiMaxLen), mmu.PermRead|mmu.PermWrite)
	} else {
		ansiBuf, _ = ctx.Mem.Read64(dest + 8)
	}

	for i := uint16(0); i < ansiLen; i++ {
		ch, _ := ctx.Mem.Read16(srcBuf + uint64(i)*2)
		if ch > 127 {
			ch = '?'
		}
		ctx.Mem.Write8(ansiBuf+uint64(i), uint8(ch))
	}
	ctx.Mem.Write8(ansiBuf+uint64(ansiLen), 0)

	ctx.Mem.Write16(dest+0, ansiLen)
	ctx.Mem.Write16(dest+2, ansiMaxLen)
	ctx.Mem.Write64(dest+8, ansiBuf)
	return StatusSuccess
}

func handleRtlFreeAnsiString(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlCreateUnicodeString(ctx *TrapContext) uint32 {
	// RtlCreateUnicodeString(PUNICODE_STRING dest, PCWSTR src)
	dest := ctx.Arg(0)
	src := ctx.Arg(1)
	if dest == 0 || src == 0 {
		ctx.SetReturn(0) // FALSE
		return StatusSuccess
	}
	// Measure wide string
	length := uint64(0)
	for {
		ch, err := ctx.Mem.Read16(src + length*2)
		if err != nil || ch == 0 {
			break
		}
		length++
	}
	byteLen := uint16(length * 2)
	bufSize := uint64(byteLen + 2)
	buf := ctx.Mem.Mmap(0, bufSize, mmu.PermRead|mmu.PermWrite)

	// Copy
	for i := uint64(0); i < length; i++ {
		ch, _ := ctx.Mem.Read16(src + i*2)
		ctx.Mem.Write16(buf+i*2, ch)
	}
	ctx.Mem.Write16(buf+length*2, 0) // null terminator

	ctx.Mem.Write16(dest+0, byteLen)
	ctx.Mem.Write16(dest+2, byteLen+2)
	ctx.Mem.Write64(dest+8, buf)
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlCompareUnicodeStrings(ctx *TrapContext) uint32 {
	s1 := ctx.Arg(0)
	l1 := uint32(ctx.Arg(1))
	s2 := ctx.Arg(2)
	l2 := uint32(ctx.Arg(3))
	caseInsensitive := ctx.Arg(4) != 0

	minLen := l1
	if l2 < minLen {
		minLen = l2
	}
	for i := uint32(0); i < minLen; i++ {
		c1, _ := ctx.Mem.Read16(s1 + uint64(i)*2)
		c2, _ := ctx.Mem.Read16(s2 + uint64(i)*2)
		if caseInsensitive {
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
		}
		if c1 != c2 {
			if c1 < c2 {
				ctx.SetReturn(^uint64(0)) // -1
			} else {
				ctx.SetReturn(1)
			}
			return StatusSuccess
		}
	}
	if l1 == l2 {
		ctx.SetReturn(0)
	} else if l1 < l2 {
		ctx.SetReturn(^uint64(0))
	} else {
		ctx.SetReturn(1)
	}
	return StatusSuccess
}

func handleRtlImageNtHeader(ctx *TrapContext) uint32 {
	base := ctx.Arg(0)
	if base == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	// Read e_lfanew
	lfanew, err := ctx.Mem.Read32(base + 0x3C)
	if err != nil {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	ntHeader := base + uint64(lfanew)
	sig, err := ctx.Mem.Read32(ntHeader)
	if err != nil || sig != 0x00004550 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	ctx.SetReturn(ntHeader)
	return StatusSuccess
}

func handleRtlImageDirectoryEntryToData(ctx *TrapContext) uint32 {
	base := ctx.Arg(0)
	_ = ctx.Arg(1)     // MappedAsImage
	dirIdx := ctx.Arg(2)
	sizePtr := ctx.Arg(3)

	if base == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	lfanew, err := ctx.Mem.Read32(base + 0x3C)
	if err != nil {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	optHdr := base + uint64(lfanew) + 4 + 20
	magic, _ := ctx.Mem.Read16(optHdr)
	var dataDirOff uint64
	if magic == 0x20B { // PE32+
		dataDirOff = optHdr + 112
	} else {
		dataDirOff = optHdr + 96
	}
	entryOff := dataDirOff + dirIdx*8
	rva, _ := ctx.Mem.Read32(entryOff)
	size, _ := ctx.Mem.Read32(entryOff + 4)
	if rva == 0 || size == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	if sizePtr != 0 {
		ctx.Mem.Write32(sizePtr, size)
	}
	ctx.SetReturn(base + uint64(rva))
	return StatusSuccess
}

func handleRtlGetNativeSystemInformation(ctx *TrapContext) uint32 {
	return handleNtQuerySystemInformation(ctx)
}

func handleNtGetTickCount(ctx *TrapContext) uint32 {
	ctx.SetReturn(uint64(time.Now().UnixMilli()) & 0xFFFFFFFF)
	return StatusSuccess
}

func handleNtFlushInstructionCache(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtGetContextThread(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtSetContextThread(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtResumeThread(ctx *TrapContext) uint32 {
	prevCount := ctx.Arg(1)
	if prevCount != 0 {
		ctx.Mem.Write32(prevCount, 1)
	}
	return StatusSuccess
}

func handleNtSuspendThread(ctx *TrapContext) uint32 {
	prevCount := ctx.Arg(1)
	if prevCount != 0 {
		ctx.Mem.Write32(prevCount, 0)
	}
	return StatusSuccess
}

func handleNtOpenProcessToken(ctx *TrapContext) uint32 {
	tokenHandle := ctx.Arg(2)
	if tokenHandle != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "ProcessToken"})
		ctx.Mem.Write64(tokenHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenThreadToken(ctx *TrapContext) uint32 {
	return StatusNotImplemented // usually means "no token"
}

func handleNtQueryInformationToken(ctx *TrapContext) uint32 {
	infoClass := uint32(ctx.Arg(1))
	outBuf := ctx.Arg(2)
	outLen := uint32(ctx.Arg(3))
	retLen := ctx.Arg(4)

	switch infoClass {
	case 1: // TokenUser - write a minimal SID
		needed := uint32(32)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, needed)
		}
		if outLen < needed {
			return 0xC0000023 // STATUS_BUFFER_TOO_SMALL
		}
		if outBuf != 0 {
			// TOKEN_USER: SID_AND_ATTRIBUTES (pointer + attributes)
			sidAddr := outBuf + 16
			ctx.Mem.Write64(outBuf, sidAddr)    // SID pointer
			ctx.Mem.Write32(outBuf+8, 0)        // Attributes
			// Minimal SID: Revision=1, SubAuthorityCount=1, Authority={0,0,0,0,0,5}, SubAuth={18} (SYSTEM)
			ctx.Mem.Write8(sidAddr+0, 1)    // Revision
			ctx.Mem.Write8(sidAddr+1, 1)    // SubAuthorityCount
			ctx.Mem.Write8(sidAddr+7, 5)    // IdentifierAuthority[5]
			ctx.Mem.Write32(sidAddr+8, 18)  // SubAuthority[0] = SYSTEM
		}
		return StatusSuccess
	case 25: // TokenElevation
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 4)
		}
		if outLen >= 4 && outBuf != 0 {
			ctx.Mem.Write32(outBuf, 1) // elevated
		}
		return StatusSuccess
	default:
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 0)
		}
		return StatusNotImplemented
	}
}

func handleNtAllocateLocallyUniqueId(ctx *TrapContext) uint32 {
	luid := ctx.Arg(0)
	if luid != 0 {
		id := uint64(time.Now().UnixNano() & 0xFFFFFFFF)
		ctx.Mem.Write32(luid, uint32(id))   // LowPart
		ctx.Mem.Write32(luid+4, 0)          // HighPart
	}
	return StatusSuccess
}

func handleNtQueryDefaultLocale(ctx *TrapContext) uint32 {
	localePtr := ctx.Arg(1)
	if localePtr != 0 {
		ctx.Mem.Write32(localePtr, 0x0409) // en-US
	}
	return StatusSuccess
}

func handleNtQueryDefaultUILanguage(ctx *TrapContext) uint32 {
	langPtr := ctx.Arg(0)
	if langPtr != 0 {
		ctx.Mem.Write16(langPtr, 0x0409) // en-US
	}
	return StatusSuccess
}

func handleNtQueryInstallUILanguage(ctx *TrapContext) uint32 {
	langPtr := ctx.Arg(0)
	if langPtr != 0 {
		ctx.Mem.Write16(langPtr, 0x0409)
	}
	return StatusSuccess
}

func handleRtlGetProcessHeaps(ctx *TrapContext) uint32 {
	// RtlGetProcessHeaps(ULONG count, PVOID* heaps)
	count := uint32(ctx.Arg(0))
	heaps := ctx.Arg(1)
	// Read process heap from PEB
	processHeap, _ := ctx.Mem.Read64(ctx.State.PEBAddr + PebProcessHeap)
	if count > 0 && heaps != 0 && processHeap != 0 {
		ctx.Mem.Write64(heaps, processHeap)
	}
	ctx.SetReturn(1) // 1 heap
	return StatusSuccess
}

func handleRtlLockHeap(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlUnlockHeap(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlValidateHeap(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlSetHeapInformation(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlQueryHeapInformation(ctx *TrapContext) uint32 {
	retLen := ctx.Arg(4)
	if retLen != 0 {
		ctx.Mem.Write32(retLen, 0)
	}
	return StatusSuccess
}

func handleRtlGetUserInfoHeap(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlSetUserValueHeap(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlCompactHeap(ctx *TrapContext) uint32 {
	ctx.SetReturn(0)
	return StatusSuccess
}
func handleRtlWalkHeap(ctx *TrapContext) uint32 {
	return 0xC0000225 // STATUS_NO_MORE_ENTRIES
}

func handleRtlInitCodePageTable(ctx *TrapContext) uint32 {
	nlsPtr := ctx.Arg(0)  // USHORT* - pointer to raw NLS data
	infoPtr := ctx.Arg(1) // CPTABLEINFO* - output struct

	if nlsPtr == 0 || infoPtr == 0 {
		return StatusSuccess
	}

	initCodePageTableAt(ctx, nlsPtr, infoPtr)
	return StatusSuccess
}

// handleRtlInitNlsTables initializes NLSTABLEINFO from raw NLS data pointers.
// VOID RtlInitNlsTables(PUSHORT AnsiNlsBase, PUSHORT OemNlsBase, PUSHORT CaseTableNlsBase, PNLSTABLEINFO TableInfo)
func handleRtlInitNlsTables(ctx *TrapContext) uint32 {
	ansiPtr := ctx.Arg(0)
	oemPtr := ctx.Arg(1)
	casePtr := ctx.Arg(2)
	infoPtr := ctx.Arg(3)

	if infoPtr == 0 {
		return StatusSuccess
	}

	// NLSTABLEINFO layout (x64):
	// +0x00 CPTABLEINFO OemTableInfo  (0x40 bytes)
	// +0x40 CPTABLEINFO AnsiTableInfo (0x40 bytes)
	// +0x80 PUSHORT UpperCaseTable
	// +0x88 PUSHORT LowerCaseTable

	if ansiPtr != 0 {
		initCodePageTableAt(ctx, ansiPtr, infoPtr+0x40)
	}
	if oemPtr != 0 {
		initCodePageTableAt(ctx, oemPtr, infoPtr)
	}
	if casePtr != 0 {
		ctx.Mem.Write64(infoPtr+0x80, casePtr)
		ctx.Mem.Write64(infoPtr+0x88, casePtr) // LowerCaseTable same as Upper for now
	}

	return StatusSuccess
}

// initCodePageTableAt is the core logic of RtlInitCodePageTable.
func initCodePageTableAt(ctx *TrapContext, nlsPtr, infoPtr uint64) {
	read16 := func(off uint64) uint16 {
		v, _ := ctx.Mem.Read16(nlsPtr + off*2)
		return v
	}

	cp := read16(1)
	ctx.Mem.Write16(infoPtr+0x00, cp)
	ctx.Mem.Write16(infoPtr+0x02, read16(2))
	ctx.Mem.Write16(infoPtr+0x04, read16(3))
	ctx.Mem.Write16(infoPtr+0x06, read16(4))
	ctx.Mem.Write16(infoPtr+0x08, read16(5))
	ctx.Mem.Write16(infoPtr+0x0A, read16(6))
	ctx.Mem.Write16(infoPtr+0x0C, 0)

	for i := uint64(0); i < 12; i++ {
		b, _ := ctx.Mem.Read8(nlsPtr + 7*2 + i)
		ctx.Mem.Write8(infoPtr+0x0E+i, b)
	}

	headerSize := read16(0)
	mbTableAddr := nlsPtr + uint64(headerSize+1)*2
	ctx.Mem.Write64(infoPtr+0x20, mbTableAddr)

	glyphSizeAddr := mbTableAddr + 256*2
	glyphSize, _ := ctx.Mem.Read16(glyphSizeAddr)
	glyphEndAddr := glyphSizeAddr + uint64(glyphSize+1)*2

	ctx.Mem.Write64(infoPtr+0x30, glyphEndAddr)

	dbcsMarker, _ := ctx.Mem.Read16(glyphEndAddr)
	if dbcsMarker != 0 {
		ctx.Mem.Write16(infoPtr+0x0C, cp)
	}

	wcTableAddr := glyphEndAddr + 2
	ctx.Mem.Write64(infoPtr+0x28, wcTableAddr)
	ctx.Mem.Write64(infoPtr+0x38, 0)
}

// handleRtlResetRtlTranslations sets PEB NLS fields from NLSTABLEINFO.
// VOID RtlResetRtlTranslations(PNLSTABLEINFO TableInfo)
func handleRtlResetRtlTranslations(ctx *TrapContext) uint32 {
	infoPtr := ctx.Arg(0)
	if infoPtr == 0 || ctx.State == nil {
		return StatusSuccess
	}

	peb := ctx.State.PEBAddr

	// AnsiTableInfo.MultiByteTable is at infoPtr+0x40+0x20
	// PEB.AnsiCodePageData = MultiByteTable - 1 (pointer to USHORT before table)
	ansiMBTable, _ := ctx.Mem.Read64(infoPtr + 0x40 + 0x20)
	if ansiMBTable > 2 {
		ctx.Mem.Write64(peb+PebAnsiCodePageData, ansiMBTable-2)
	}

	// OemTableInfo.MultiByteTable is at infoPtr+0x00+0x20
	oemMBTable, _ := ctx.Mem.Read64(infoPtr + 0x20)
	if oemMBTable > 2 {
		ctx.Mem.Write64(peb+PebOemCodePageData, oemMBTable-2)
	}

	// UpperCaseTable is at infoPtr+0x80
	ucTable, _ := ctx.Mem.Read64(infoPtr + 0x80)
	if ucTable != 0 {
		ctx.Mem.Write64(peb+PebUnicodeCaseTableData, ucTable)
	}

	return StatusSuccess
}

func handleRtlFlsAlloc(ctx *TrapContext) uint32 {
	// RtlFlsAlloc(callback, *index_out)
	// RCX = callback (ignored), RDX = pointer to output index
	indexPtr := ctx.Arg(1)

	// Use PEB FlsBitmap to allocate an index
	pebAddr := ctx.State.PEBAddr
	flsBitmapPtr, _ := ctx.Mem.Read64(pebAddr + PebFlsBitmap)
	if flsBitmapPtr == 0 {
		if indexPtr != 0 {
			ctx.Mem.Write32(indexPtr, 0xFFFFFFFF)
		}
		return 0xC0000017 // STATUS_NO_MEMORY
	}

	// RtlFindClearBitsAndSet on the FLS bitmap
	sizeOfBitMap, _ := ctx.Mem.Read32(flsBitmapPtr)
	bufferAddr, _ := ctx.Mem.Read64(flsBitmapPtr + 8)
	idx := uint32(0xFFFFFFFF)
	for i := uint32(0); i < sizeOfBitMap; i++ {
		wordIdx := i / 32
		bitIdx := i % 32
		word, _ := ctx.Mem.Read32(bufferAddr + uint64(wordIdx)*4)
		if word&(1<<bitIdx) == 0 {
			word |= 1 << bitIdx
			ctx.Mem.Write32(bufferAddr+uint64(wordIdx)*4, word)
			idx = i
			break
		}
	}
	if idx == 0xFFFFFFFF {
		if indexPtr != 0 {
			ctx.Mem.Write32(indexPtr, 0xFFFFFFFF)
		}
		return 0xC0000017 // STATUS_NO_MEMORY
	}

	ensureFlsData(ctx)

	if indexPtr != 0 {
		ctx.Mem.Write32(indexPtr, idx)
	}
	if ctx.Trace {
		fmt.Fprintf(os.Stderr, "  RtlFlsAlloc → index=%d\n", idx)
	}
	return StatusSuccess
}

func handleRtlFlsFree(ctx *TrapContext) uint32 {
	idx := uint32(ctx.Arg(0))
	flsDataPtr, _ := ctx.Mem.Read64(ctx.State.TEBAddr + TebFlsData)
	if flsDataPtr != 0 && idx < 256 {
		ctx.Mem.Write64(flsDataPtr+8+uint64(idx)*8, 0)
	}
	// Clear bit in PEB FlsBitmap
	pebAddr := ctx.State.PEBAddr
	flsBitmapPtr, _ := ctx.Mem.Read64(pebAddr + PebFlsBitmap)
	if flsBitmapPtr != 0 {
		bufferAddr, _ := ctx.Mem.Read64(flsBitmapPtr + 8)
		if bufferAddr != 0 {
			wordIdx := idx / 32
			bitIdx := idx % 32
			word, _ := ctx.Mem.Read32(bufferAddr + uint64(wordIdx)*4)
			word &^= 1 << bitIdx
			ctx.Mem.Write32(bufferAddr+uint64(wordIdx)*4, word)
		}
	}
	return StatusSuccess
}
func handleRtlFlsGetValue(ctx *TrapContext) uint32 {
	// RtlFlsGetValue(index, *value_out)
	// RCX = index, RDX = pointer to output value
	idx := uint32(ctx.Arg(0))
	outPtr := ctx.Arg(1)
	flsDataPtr, _ := ctx.Mem.Read64(ctx.State.TEBAddr + TebFlsData)
	var val uint64
	if flsDataPtr != 0 && idx < 256 {
		val, _ = ctx.Mem.Read64(flsDataPtr + 8 + uint64(idx)*8)
	}
	if outPtr != 0 {
		ctx.Mem.Write64(outPtr, val)
	}
	return StatusSuccess
}
func handleRtlFlsSetValue(ctx *TrapContext) uint32 {
	// RtlFlsSetValue(index, value)
	// RCX = index, RDX = value
	idx := uint32(ctx.Arg(0))
	val := ctx.Arg(1)

	ensureFlsData(ctx)

	flsDataPtr, _ := ctx.Mem.Read64(ctx.State.TEBAddr + TebFlsData)
	if flsDataPtr != 0 && idx < 256 {
		ctx.Mem.Write64(flsDataPtr+8+uint64(idx)*8, val)
	}
	return StatusSuccess
}

// ensureFlsData allocates the FLS data array in guest memory if not yet created.
func ensureFlsData(ctx *TrapContext) {
	flsDataPtr, _ := ctx.Mem.Read64(ctx.State.TEBAddr + TebFlsData)
	if flsDataPtr != 0 {
		return
	}
	// Allocate 256 slots + 8 bytes header = 2056 bytes
	const flsArraySize = 8 + 256*8
	addr := ctx.Mem.Mmap(0, flsArraySize, 0x3) // RW
	if addr == 0 {
		return
	}
	// Clear to zero
	for i := uint64(0); i < flsArraySize; i += 8 {
		ctx.Mem.Write64(addr+i, 0)
	}
	// Store in TEB
	ctx.Mem.Write64(ctx.State.TEBAddr+TebFlsData, addr)
}
func handleRtlProcessFlsData(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlExitUserProcess(ctx *TrapContext) uint32 {
	code := uint32(ctx.Arg(0))
	os.Exit(int(code))
	return StatusSuccess
}

func handleRtlExitUserThread(ctx *TrapContext) uint32 {
	ctx.CPU.Stop()
	return StatusSuccess
}

func handleRtlNormalizeProcessParams(ctx *TrapContext) uint32 {
	params := ctx.Arg(0)
	ctx.SetReturn(params)
	return StatusSuccess
}

func handleRtlIsProcessorFeaturePresent(ctx *TrapContext) uint32 {
	feature := uint32(ctx.Arg(0))
	switch feature {
	case 10: // PF_COMPARE_EXCHANGE_DOUBLE
		ctx.SetReturn(1)
	case 23: // PF_FASTFAIL_AVAILABLE
		ctx.SetReturn(1)
	default:
		ctx.SetReturn(0)
	}
	return StatusSuccess
}

func handleRtlCaptureContext(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlUnwind(ctx *TrapContext) uint32         { return StatusSuccess }
func handleRtlUnwindEx(ctx *TrapContext) uint32        { return StatusSuccess }
func handleRtlLookupFunctionEntry(ctx *TrapContext) uint32 {
	ctx.SetReturn(0)
	return StatusSuccess
}
func handleRtlRestoreContext(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlRaiseException(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlRaiseStatus(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlPcToFileHeader(ctx *TrapContext) uint32 {
	ctx.SetReturn(0)
	return StatusSuccess
}

func handleRtlGetEnabledExtendedFeatures(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // no extended features
	return StatusSuccess
}

func handleRtlSetUnhandledExceptionFilter(ctx *TrapContext) uint32 { return StatusSuccess }

func handleNtCreateSemaphore(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	objAttr := ctx.Arg(2)
	initialCount := int32(ctx.Arg(3))
	maxCount := int32(ctx.Arg(4))
	if maxCount <= 0 {
		maxCount = 0x7fffffff
	}

	sem := NewSemaphore(initialCount, maxCount)

	var name string
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}

	var h Handle
	if name != "" {
		var isNew bool
		h, isNew = ctx.Handles.AllocNamed(name, sem)
		if !isNew {
			if handlePtr != 0 {
				ctx.Mem.Write64(handlePtr, uint64(h))
			}
			return 0x40000000 // STATUS_OBJECT_NAME_EXISTS
		}
	} else {
		h = ctx.Handles.Alloc(sem)
	}

	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtReleaseSemaphore(ctx *TrapContext) uint32 {
	// NtReleaseSemaphore(SemaphoreHandle, ReleaseCount, PreviousCount*)
	h := Handle(ctx.Arg(0))
	releaseCount := int32(ctx.Arg(1))
	pPrevCount := ctx.Arg(2)
	if releaseCount <= 0 {
		releaseCount = 1
	}
	if sh := ctx.Handles.GetSemaphore(h); sh != nil {
		prev, _ := sh.Release(releaseCount)
		if pPrevCount != 0 {
			ctx.Mem.Write32(pPrevCount, uint32(prev))
		}
	}
	return StatusSuccess
}

func handleNtOpenEvent(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	objAttr := ctx.Arg(2)

	var name string
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}

	h := ctx.Handles.GetNamed(name)
	if h == 0 {
		return StatusObjectNameNotFound
	}
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenMutant(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	objAttr := ctx.Arg(2)

	var name string
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}

	h := ctx.Handles.GetNamed(name)
	if h == 0 {
		return StatusObjectNameNotFound
	}
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenSemaphore(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	objAttr := ctx.Arg(2)

	var name string
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}

	h := ctx.Handles.GetNamed(name)
	if h == 0 {
		return StatusObjectNameNotFound
	}
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenSection(ctx *TrapContext) uint32 {
	return 0xC0000034
}

func handleNtQueryAttributesFile(ctx *TrapContext) uint32 {
	return 0xC0000034 // not found
}

func handleNtOpenProcess(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "Process"})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtSetInformationProcess(ctx *TrapContext) uint32 { return StatusSuccess }
func handleNtSetInformationThread(ctx *TrapContext) uint32  { return StatusSuccess }

func handleNtCreateTimer(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "Timer"})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtSetTimer(ctx *TrapContext) uint32    { return StatusSuccess }
func handleNtCancelTimer(ctx *TrapContext) uint32 { return StatusSuccess }

func handleLdrLoadDll(ctx *TrapContext) uint32 {
	// LdrLoadDll(path, flags, moduleName*, handle*)
	handlePtr := ctx.Arg(3)
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, 0) // NULL = not found
	}
	return StatusNotImplemented
}

func handleLdrGetDllHandleEx(ctx *TrapContext) uint32 {
	// LdrGetDllHandleEx(flags, path, unused, moduleName*, handle*)
	_ = ctx.Arg(0) // flags
	moduleNamePtr := ctx.Arg(3) // UNICODE_STRING*
	handlePtr := ctx.Arg(4)

	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, 0)
	}

	if moduleNamePtr == 0 {
		return 0xC0000135 // STATUS_DLL_NOT_FOUND
	}

	nameStr := readGuestUnicodeString(ctx.Mem, moduleNamePtr)
	nameStr = strings.ToLower(nameStr)
	if idx := strings.LastIndexAny(nameStr, "\\/"); idx >= 0 {
		nameStr = nameStr[idx+1:]
	}
	if !strings.HasSuffix(nameStr, ".dll") {
		nameStr += ".dll"
	}

	base := findModuleByName(ctx, nameStr)
	if base == 0 {
		return 0xC0000135 // STATUS_DLL_NOT_FOUND
	}
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, base)
	}
	return StatusSuccess
}

func handleLdrAddRefDll(ctx *TrapContext) uint32 { return StatusSuccess }

func handleLdrGetDllPath(ctx *TrapContext) uint32 {
	pathPtr := ctx.Arg(1)
	if pathPtr != 0 {
		ctx.Mem.Write64(pathPtr, 0)
	}
	return StatusSuccess
}

func handleLdrGetDllFullName(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleRtlDosPathNameToNtPathName_U(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE (but won't fill in the path properly)
	return StatusSuccess
}

func handleRtlDosPathNameToNtPathName_U_WithStatus(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlGetCurrentDirectory_U(ctx *TrapContext) uint32 {
	bufLen := uint32(ctx.Arg(0))
	buf := ctx.Arg(1)
	cwd := `C:\`
	if buf != 0 && bufLen >= uint32(len(cwd)*2+2) {
		for i, ch := range cwd {
			ctx.Mem.Write16(buf+uint64(i)*2, uint16(ch))
		}
		ctx.Mem.Write16(buf+uint64(len(cwd))*2, 0)
	}
	ctx.SetReturn(uint64(len(cwd) * 2))
	return StatusSuccess
}

func handleRtlSetCurrentDirectory_U(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlGetFullPathName_U(ctx *TrapContext) uint32 {
	ctx.SetReturn(0)
	return StatusSuccess
}

func handleRtlDetermineDosPathNameType_U(ctx *TrapContext) uint32 {
	ctx.SetReturn(5) // RtlPathTypeRootLocalDevice
	return StatusSuccess
}

func handleRtlInitializeBitMap(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlSetBits(ctx *TrapContext) uint32          { return StatusSuccess }
func handleRtlClearBits(ctx *TrapContext) uint32        { return StatusSuccess }
func handleRtlAreBitsSet(ctx *TrapContext) uint32 {
	ctx.SetReturn(1)
	return StatusSuccess
}
func handleRtlAreBitsClear(ctx *TrapContext) uint32 {
	ctx.SetReturn(1)
	return StatusSuccess
}

func handleRtlGetThreadErrorMode(ctx *TrapContext) uint32 {
	ctx.SetReturn(0)
	return StatusSuccess
}

func handleRtlSetThreadErrorMode(ctx *TrapContext) uint32 {
	oldMode := ctx.Arg(1)
	if oldMode != 0 {
		ctx.Mem.Write32(oldMode, 0)
	}
	return StatusSuccess
}

func handleRtlWow64GetProcessMachines(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

// Wine-specific stubs
func handleWineGetVersion(ctx *TrapContext) uint32 {
	// wine_get_version() returns pointer to version string
	ver := "9.0"
	buf := ctx.Mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
	for i, b := range []byte(ver) {
		ctx.Mem.Write8(buf+uint64(i), b)
	}
	ctx.Mem.Write8(buf+uint64(len(ver)), 0)
	ctx.SetReturn(buf)
	return StatusSuccess
}

func handleWineServerCall(ctx *TrapContext) uint32 {
	// wine_server_call(req) - return STATUS_NOT_IMPLEMENTED
	ctx.SetReturn(0xC0000002)
	return StatusSuccess
}

func handleWineDbgGetChannelFlags(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // no debug channels
	return StatusSuccess
}

func handleWineDbgHeader(ctx *TrapContext) uint32 {
	// Return pointer to an empty string (the NUL at PEB+0x100 which is always 0)
	ctx.SetReturn(ctx.State.PEBAddr + 0x100)
	return StatusSuccess
}
func handleWineDbgOutput(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // 0 chars written
	return StatusSuccess
}
func handleWineDbgStrdup(ctx *TrapContext) uint32 {
	ctx.SetReturn(ctx.Arg(0)) // return same pointer
	return StatusSuccess
}

func handleRtlOpenCurrentUser(ctx *TrapContext) uint32 {
	// RtlOpenCurrentUser(ACCESS_MASK access, PHANDLE result)
	// Opens \\Registry\\User\\.Default
	_ = ctx.Arg(0) // access
	handlePtr := ctx.Arg(1)

	key := ctx.Reg.OpenKey("\\Registry\\User\\.Default")
	if key == nil {
		// Create a stub key so callers get something valid
		ctx.Reg.CreateKey("\\Registry\\User\\.Default")
		key = ctx.Reg.OpenKey("\\Registry\\User\\.Default")
	}
	if key != nil {
		h := ctx.Handles.Alloc(&RegistryKeyHandle{Key: key})
		if handlePtr != 0 {
			ctx.Mem.Write64(handlePtr, uint64(h))
		}
		return StatusSuccess
	}
	return StatusObjectNameNotFound
}

func handleRtlQueryDynamicTimeZoneInformation(ctx *TrapContext) uint32 {
	// RTL_DYNAMIC_TIME_ZONE_INFORMATION is 0x80 (128) bytes
	infoPtr := ctx.Arg(0)
	if infoPtr != 0 {
		// Zero out the structure (UTC timezone)
		for i := uint64(0); i < 128; i++ {
			ctx.Mem.Write8(infoPtr+i, 0)
		}
	}
	return StatusSuccess
}

func handleWineNtToUnixFileName(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleWineUnixToNtFileName(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleRtlCreateEnvironment(ctx *TrapContext) uint32 {
	envPtr := ctx.Arg(1)
	if envPtr != 0 {
		// Allocate a minimal environment block: just null terminator
		envBuf := ctx.Mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write16(envBuf, 0)
		ctx.Mem.Write64(envPtr, envBuf)
	}
	return StatusSuccess
}

func handleRtlDestroyEnvironment(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlSetEnvironmentVariable(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlQueryEnvironmentVariable_U(ctx *TrapContext) uint32 {
	return 0xC0000100 // STATUS_VARIABLE_NOT_FOUND
}

func handleRtlExpandEnvironmentStrings_U(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleRtlCreateProcessParametersEx(ctx *TrapContext) uint32 {
	paramsPtr := ctx.Arg(0)
	if paramsPtr != 0 {
		params := ctx.Mem.Mmap(0, 1024, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write32(params, 1024) // MaximumLength
		ctx.Mem.Write32(params+4, 512) // Length
		ctx.Mem.Write64(paramsPtr, params)
	}
	return StatusSuccess
}

func handleRtlDestroyProcessParameters(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlRunOnceBeginInitialize(ctx *TrapContext) uint32 {
	return StatusSuccess // proceed with initialization
}

func handleRtlRunOnceComplete(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlRunOnceExecuteOnce(ctx *TrapContext) uint32 { return StatusSuccess }

func handleNtCreateIoCompletion(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "IoCompletion"})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtSetIoCompletion(ctx *TrapContext) uint32     { return StatusSuccess }
func handleNtRemoveIoCompletion(ctx *TrapContext) uint32  { return StatusSuccess }
func handleNtRemoveIoCompletionEx(ctx *TrapContext) uint32 { return StatusSuccess }
func handleNtCancelIoFile(ctx *TrapContext) uint32        { return StatusSuccess }
func handleNtCancelIoFileEx(ctx *TrapContext) uint32      { return StatusSuccess }

func handleNtCreateDirectoryObject(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "Directory"})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenDirectoryObject(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "Directory"})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtCreateSymbolicLinkObject(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "SymLink"})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenSymbolicLinkObject(ctx *TrapContext) uint32 {
	return 0xC0000034
}

func handleNtQuerySymbolicLinkObject(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleNtSetSecurityObject(ctx *TrapContext) uint32     { return StatusSuccess }
func handleNtQuerySecurityObject(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleNtSetInformationObject(ctx *TrapContext) uint32 { return StatusSuccess }

func handleNtLockFile(ctx *TrapContext) uint32 { return StatusSuccess }
func handleNtUnlockFile(ctx *TrapContext) uint32 { return StatusSuccess }

func handleNtCreateMailslotFile(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleNtCreateNamedPipeFile(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleNtFsControlFile(ctx *TrapContext) uint32 {
	ioStatus := ctx.Arg(3)
	if ioStatus != 0 {
		writeIOStatus(ctx.Mem, ioStatus, StatusNotImplemented, 0)
	}
	return StatusNotImplemented
}

func handleNtPowerInformation(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleNtQueueApcThread(ctx *TrapContext) uint32 { return StatusSuccess }

func handleNtGetNlsSectionPtr(ctx *TrapContext) uint32 {
	nlsType := ctx.Arg(0)
	nlsID := ctx.Arg(1)
	ptrOut := ctx.Arg(3)
	sizeOut := ctx.Arg(4)

	ravelog.Logf("[ntapi] NtGetNlsSectionPtr type=%d id=%d ptrOut=0x%x sizeOut=0x%x\n",
		nlsType, nlsID, ptrOut, sizeOut)

	if ctx.Disp == nil || ctx.Disp.sysRoot == "" {
		return StatusNotImplemented
	}

	var data []byte
	var err error

	switch nlsType {
	case 11: // NLS_SECTION_CODEPAGE - c_XXXX.nls
		data, err = ctx.Disp.loadNlsFile(uint32(nlsID))
	case 9: // NLS_SECTION_SORTKEYS - build minimal valid sort key table
		data = BuildSortKeyData()
		err = nil
	case 12: // NLS_SECTION_NORMALIZE - normNFC/NFD/NFKC/NFKD/IDNA
		nameMap := map[uint64]string{
			1: "normnfc.nls", 2: "normnfd.nls",
			5: "normnfkc.nls", 6: "normnfkd.nls",
			13: "normidna.nls",
		}
		if fname, ok := nameMap[nlsID]; ok {
			path := ctx.Disp.sysRoot + "/" + fname
			data, err = os.ReadFile(path)
		} else {
			return StatusNotImplemented
		}
	default:
		return StatusNotImplemented
	}

	if err != nil {
		ravelog.Logf("[ntapi] NtGetNlsSectionPtr: failed to load NLS type=%d id=%d: %v\n", nlsType, nlsID, err)
		return StatusNotImplemented
	}

	// Map the NLS data into guest memory with a page of padding before
	// the data so that Wine's negative-offset accesses (ptr[-n]) work.
	size := uint64(len(data))
	pad := uint64(mmu.PageSize)
	allocSize := (size + pad + mmu.PageSize - 1) & mmu.PageMask
	base := ctx.Mem.Mmap(0, allocSize, mmu.PermRead|mmu.PermWrite)
	dataAddr := base + pad
	ctx.Mem.WriteBytes(dataAddr, data)

	if ptrOut != 0 {
		ctx.Mem.Write64(ptrOut, dataAddr)
	}
	if sizeOut != 0 {
		ctx.Mem.Write64(sizeOut, size)
	}

	ravelog.Logf("[ntapi] NtGetNlsSectionPtr: mapped type=%d id=%d at 0x%x size=0x%x\n", nlsType, nlsID, dataAddr, size)
	return StatusSuccess
}

func handleRtlGetLocaleFileMappingAddress(ctx *TrapContext) uint32 {
	// NTSTATUS RtlGetLocaleFileMappingAddress(
	//   PVOID *BaseAddress,           // RCX - OUT
	//   PULONG DefaultLocaleId,       // RDX - OUT (LCID)
	//   PLARGE_INTEGER DefaultCasingTableSize // R8 - OUT
	// )
	baseAddrPtr := ctx.Arg(0)
	localeIdPtr := ctx.Arg(1)
	casingSizePtr := ctx.Arg(2)

	// Load locale.nls from sysroot (Wine uses locale.nls, not l_intl.nls)
	var data []byte
	if ctx.Disp != nil && ctx.Disp.sysRoot != "" {
		path := ctx.Disp.sysRoot + "/locale.nls"
		if d, err := os.ReadFile(path); err == nil {
			data = d
		}
	}
	if data == nil {
		// Minimal locale data: just a zeroed page
		data = make([]byte, 4096)
	}

	// Allocate with one extra page of padding before the data so that
	// small negative offsets from the returned pointer read valid memory
	// (Wine's kernelbase accesses ptr[-n] for header fields).
	pad := mmu.PageSize
	size := (uint64(len(data)) + uint64(pad) + mmu.PageSize - 1) & mmu.PageMask
	base := ctx.Mem.Mmap(0, size, mmu.PermRead|mmu.PermWrite)
	dataAddr := base + uint64(pad)
	ctx.Mem.WriteBytes(dataAddr, data)

	ravelog.Logf("[ntapi] RtlGetLocaleFileMappingAddress: mapped locale.nls at 0x%x size=0x%x\n", dataAddr, len(data))

	if baseAddrPtr != 0 {
		ctx.Mem.Write64(baseAddrPtr, dataAddr)
	}
	if localeIdPtr != 0 {
		ctx.Mem.Write32(localeIdPtr, 0x0409) // en-US
	}
	if casingSizePtr != 0 {
		ctx.Mem.Write64(casingSizePtr, uint64(len(data)))
	}

	return StatusSuccess
}

func handleRtlGetProductInfo(ctx *TrapContext) uint32 {
	retPtr := ctx.Arg(4)
	if retPtr != 0 {
		ctx.Mem.Write32(retPtr, 0x65) // PRODUCT_CORE = Windows 10 Home
	}
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlGetSystemPreferredUILanguages(ctx *TrapContext) uint32 {
	numLangs := ctx.Arg(1)
	buf := ctx.Arg(2)
	bufLen := ctx.Arg(3)
	if numLangs != 0 {
		ctx.Mem.Write32(numLangs, 1)
	}
	if buf != 0 && bufLen != 0 {
		lang := "en-US"
		maxLen, _ := ctx.Mem.Read32(bufLen)
		if maxLen >= uint32((len(lang)+2)*2) {
			for i, ch := range lang {
				ctx.Mem.Write16(buf+uint64(i)*2, uint16(ch))
			}
			ctx.Mem.Write16(buf+uint64(len(lang))*2, 0)
			ctx.Mem.Write16(buf+uint64(len(lang)+1)*2, 0)
		}
		ctx.Mem.Write32(bufLen, uint32((len(lang)+2)*2))
	}
	return StatusSuccess
}

func handleRtlGetUserPreferredUILanguages(ctx *TrapContext) uint32 {
	return handleRtlGetSystemPreferredUILanguages(ctx)
}

func handleRtlGetProcessPreferredUILanguages(ctx *TrapContext) uint32 {
	return handleRtlGetSystemPreferredUILanguages(ctx)
}

func handleRtlGetThreadPreferredUILanguages(ctx *TrapContext) uint32 {
	return handleRtlGetSystemPreferredUILanguages(ctx)
}

func handleRtlGetSystemTimePrecise(ctx *TrapContext) uint32 {
	// Returns 100ns intervals since 1601-01-01
	now := time.Now()
	epoch := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	intervals := now.Sub(epoch).Nanoseconds() / 100
	ctx.SetReturn(uint64(intervals))
	return StatusSuccess
}

func handleRtlTimeFieldsToTime(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlTimeToTimeFields(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlQueryUnbiasedInterruptTime(ctx *TrapContext) uint32 {
	ptr := ctx.Arg(0)
	if ptr != 0 {
		ctx.Mem.Write64(ptr, uint64(time.Now().UnixNano()/100))
	}
	return StatusSuccess
}

func handleNtSetInformationToken(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlCreateSecurityDescriptor(ctx *TrapContext) uint32 {
	sd := ctx.Arg(0)
	if sd != 0 {
		ctx.Mem.Write8(sd, 1) // Revision
	}
	return StatusSuccess
}

func handleRtlSetDaclSecurityDescriptor(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlCreateAcl(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlAddAccessAllowedAce(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlAddAccessAllowedAceEx(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlAllocateAndInitializeSid(ctx *TrapContext) uint32 {
	sidPtr := ctx.Arg(0)
	if sidPtr != 0 {
		sid := ctx.Mem.Mmap(0, 28, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write8(sid, 1) // Revision
		ctx.Mem.Write8(sid+1, 1) // SubAuthorityCount
		ctx.Mem.Write64(sidPtr, sid)
	}
	return StatusSuccess
}

func handleRtlFreeSid(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlCopySid(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlEqualSid(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}
func handleRtlLengthSid(ctx *TrapContext) uint32 {
	ctx.SetReturn(12)
	return StatusSuccess
}
func handleRtlInitializeSid(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlValidSid(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}
func handleRtlSubAuthorityCountSid(ctx *TrapContext) uint32 {
	sid := ctx.Arg(0)
	if sid != 0 {
		ctx.SetReturn(sid + 1) // pointer to SubAuthorityCount byte
	}
	return StatusSuccess
}
func handleRtlSubAuthoritySid(ctx *TrapContext) uint32 {
	sid := ctx.Arg(0)
	idx := ctx.Arg(1)
	if sid != 0 {
		ctx.SetReturn(sid + 8 + idx*4)
	}
	return StatusSuccess
}
func handleRtlIdentifierAuthoritySid(ctx *TrapContext) uint32 {
	sid := ctx.Arg(0)
	if sid != 0 {
		ctx.SetReturn(sid + 2) // pointer to IdentifierAuthority
	}
	return StatusSuccess
}

func handleNtPrivilegeCheck(ctx *TrapContext) uint32 {
	result := ctx.Arg(2)
	if result != 0 {
		ctx.Mem.Write8(result, 1) // privileges held
	}
	return StatusSuccess
}

func handleNtAdjustPrivilegesToken(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlQueryActivationContextApplicationSettings(ctx *TrapContext) uint32 {
	return 0xC015000F // STATUS_SXS_KEY_NOT_FOUND
}
func handleRtlFindActivationContextSectionString(ctx *TrapContext) uint32 {
	return 0xC000008B // STATUS_SXS_SECTION_NOT_FOUND
}
func handleRtlFindActivationContextSectionGuid(ctx *TrapContext) uint32 {
	return 0xC000008B
}
func handleRtlActivateActivationContext(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlDeactivateActivationContext(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlGetActiveActivationContext(ctx *TrapContext) uint32 {
	cookie := ctx.Arg(0)
	if cookie != 0 {
		ctx.Mem.Write64(cookie, 0)
	}
	return StatusSuccess
}
func handleRtlAddRefActivationContext(ctx *TrapContext) uint32     { return StatusSuccess }
func handleRtlReleaseActivationContext(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlCreateActivationContext(ctx *TrapContext) uint32     { return StatusSuccess }
func handleRtlZombifyActivationContext(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlFreeActivationContextStack(ctx *TrapContext) uint32  { return StatusSuccess }
func handleRtlQueryInformationActivationContext(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleRtlQueueWorkItem(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlCreateTimer(ctx *TrapContext) uint32 {
	timerPtr := ctx.Arg(1)
	if timerPtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "RtlTimer"})
		ctx.Mem.Write64(timerPtr, uint64(h))
	}
	return StatusSuccess
}

func handleRtlDeleteTimer(ctx *TrapContext) uint32         { return StatusSuccess }
func handleRtlUpdateTimer(ctx *TrapContext) uint32         { return StatusSuccess }
func handleRtlCreateTimerQueue(ctx *TrapContext) uint32 {
	queuePtr := ctx.Arg(0)
	if queuePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "TimerQueue"})
		ctx.Mem.Write64(queuePtr, uint64(h))
	}
	return StatusSuccess
}
func handleRtlDeleteTimerQueueEx(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlRegisterWait(ctx *TrapContext) uint32 {
	waitPtr := ctx.Arg(0)
	if waitPtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "Wait"})
		ctx.Mem.Write64(waitPtr, uint64(h))
	}
	return StatusSuccess
}
func handleRtlDeregisterWait(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlDeregisterWaitEx(ctx *TrapContext) uint32  { return StatusSuccess }

func handleRtlSetIoCompletionCallback(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlGUIDFromString(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlFindMessage(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleRtlFormatMessage(ctx *TrapContext) uint32 {
	return StatusNotImplemented
}

func handleRtlUTF8ToUnicodeN(ctx *TrapContext) uint32 {
	dst := ctx.Arg(0)
	dstMax := uint32(ctx.Arg(1))
	resultLenPtr := ctx.Arg(2)
	src := ctx.Arg(3)
	srcLen := uint32(ctx.Arg(4))

	written := uint32(0)
	i := uint32(0)
	for i < srcLen && written+2 <= dstMax {
		b, err := ctx.Mem.Read8(src + uint64(i))
		if err != nil {
			break
		}
		if b < 0x80 {
			if dst != 0 {
				ctx.Mem.Write16(dst+uint64(written), uint16(b))
			}
			written += 2
			i++
		} else if b < 0xE0 && i+1 < srcLen {
			b2, _ := ctx.Mem.Read8(src + uint64(i+1))
			ch := uint16(b&0x1F)<<6 | uint16(b2&0x3F)
			if dst != 0 {
				ctx.Mem.Write16(dst+uint64(written), ch)
			}
			written += 2
			i += 2
		} else if b < 0xF0 && i+2 < srcLen {
			b2, _ := ctx.Mem.Read8(src + uint64(i+1))
			b3, _ := ctx.Mem.Read8(src + uint64(i+2))
			ch := uint16(b&0x0F)<<12 | uint16(b2&0x3F)<<6 | uint16(b3&0x3F)
			if dst != 0 {
				ctx.Mem.Write16(dst+uint64(written), ch)
			}
			written += 2
			i += 3
		} else {
			if dst != 0 {
				ctx.Mem.Write16(dst+uint64(written), '?')
			}
			written += 2
			i++
		}
	}
	if resultLenPtr != 0 {
		ctx.Mem.Write32(resultLenPtr, written)
	}
	return StatusSuccess
}

func handleRtlUnicodeToUTF8N(ctx *TrapContext) uint32 {
	dst := ctx.Arg(0)
	dstMax := uint32(ctx.Arg(1))
	resultLenPtr := ctx.Arg(2)
	src := ctx.Arg(3)
	srcLen := uint32(ctx.Arg(4))

	written := uint32(0)
	for i := uint32(0); i+2 <= srcLen && written < dstMax; i += 2 {
		ch, _ := ctx.Mem.Read16(src + uint64(i))
		if ch < 0x80 {
			if dst != 0 {
				ctx.Mem.Write8(dst+uint64(written), uint8(ch))
			}
			written++
		} else if ch < 0x800 {
			if written+2 > dstMax {
				break
			}
			if dst != 0 {
				ctx.Mem.Write8(dst+uint64(written), uint8(0xC0|(ch>>6)))
				ctx.Mem.Write8(dst+uint64(written+1), uint8(0x80|(ch&0x3F)))
			}
			written += 2
		} else {
			if written+3 > dstMax {
				break
			}
			if dst != 0 {
				ctx.Mem.Write8(dst+uint64(written), uint8(0xE0|(ch>>12)))
				ctx.Mem.Write8(dst+uint64(written+1), uint8(0x80|((ch>>6)&0x3F)))
				ctx.Mem.Write8(dst+uint64(written+2), uint8(0x80|(ch&0x3F)))
			}
			written += 3
		}
	}
	if resultLenPtr != 0 {
		ctx.Mem.Write32(resultLenPtr, written)
	}
	return StatusSuccess
}

func handleRtlIsNormalizedString(ctx *TrapContext) uint32 {
	resultPtr := ctx.Arg(2)
	if resultPtr != 0 {
		ctx.Mem.Write8(resultPtr, 1) // already normalized
	}
	return StatusSuccess
}

func handleRtlNormalizeString(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlSleepConditionVariableCS(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlSleepConditionVariableSRW(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlWaitOnAddress(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleDbgBreakPoint(ctx *TrapContext) uint32 {
	return StatusSuccess // ignore breakpoints
}

func handleNtNotifyChangeKey(ctx *TrapContext) uint32 { return StatusSuccess }
func handleNtNotifyChangeDirectoryFile(ctx *TrapContext) uint32 { return StatusSuccess }

// Etw stubs
func handleEtwEventRegister(ctx *TrapContext) uint32     { return StatusSuccess }
func handleEtwEventUnregister(ctx *TrapContext) uint32   { return StatusSuccess }
func handleEtwEventWrite(ctx *TrapContext) uint32        { return StatusSuccess }
func handleEtwEventEnabled(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // not enabled
	return StatusSuccess
}

func handleNtQueryFullAttributesFile(ctx *TrapContext) uint32 {
	return 0xC0000034 // STATUS_OBJECT_NAME_NOT_FOUND
}

func handleNtCompareObjects(ctx *TrapContext) uint32 {
	h1 := ctx.Arg(0)
	h2 := ctx.Arg(1)
	if h1 == h2 {
		return StatusSuccess
	}
	return StatusNotImplemented
}

func handleNtSetSystemInformation(ctx *TrapContext) uint32 { return StatusSuccess }
func handleNtSetSystemTime(ctx *TrapContext) uint32        { return StatusSuccess }

func handleRtlWow64EnableFsRedirection(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlWow64EnableFsRedirectionEx(ctx *TrapContext) uint32 { return StatusSuccess }

// handleLdrDisableThreadCalloutsForDll disables DLL_THREAD_ATTACH/DETACH notifications.
func handleLdrDisableThreadCalloutsForDll(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // STATUS_SUCCESS
	return StatusSuccess
}

// handleLdrFindResource_U navigates the PE resource directory tree.
// LdrFindResource_U(HMODULE hModule, LDR_RESOURCE_INFO *info, ULONG level, IMAGE_RESOURCE_DATA_ENTRY **entry)
func handleLdrFindResource_U(ctx *TrapContext) uint32 {
	hModule := ctx.Arg(0) // module base address
	infoPtr := ctx.Arg(1) // LDR_RESOURCE_INFO*
	level := ctx.Arg(2)   // number of levels (typically 3)
	entryPtr := ctx.Arg(3) // output IMAGE_RESOURCE_DATA_ENTRY**

	if hModule == 0 || entryPtr == 0 {
		return 0xC0000135 // STATUS_DLL_NOT_FOUND
	}

	// Read resource directory RVA from PE headers in guest memory
	rsrcRVA, rsrcSize := peResourceDir(ctx.Mem, hModule)
	if rsrcRVA == 0 || rsrcSize == 0 {
		return 0xC0000135 // STATUS_RESOURCE_TYPE_NOT_FOUND
	}
	rsrcBase := hModule + uint64(rsrcRVA)

	// LDR_RESOURCE_INFO: Type (+0), Name (+8), Language (+16) - all ULONG_PTR (8 bytes on x64)
	var resType, resName, resLang uint64
	if infoPtr != 0 {
		resType, _ = ctx.Mem.Read64(infoPtr)
		if level >= 2 {
			resName, _ = ctx.Mem.Read64(infoPtr + 8)
		}
		if level >= 3 {
			resLang, _ = ctx.Mem.Read64(infoPtr + 16)
		}
	}

	// Navigate resource directory tree
	dirAddr := rsrcBase

	// Level 1: find type
	if level >= 1 {
		found, isDir := findResourceEntry(ctx.Mem, dirAddr, rsrcBase, uint32(resType))
		if found == 0 {
			return 0xC0000135 // STATUS_RESOURCE_TYPE_NOT_FOUND
		}
		if !isDir {
			// Leaf at level 1 - unlikely but handle it
			ctx.Mem.Write64(entryPtr, found)
			return StatusSuccess
		}
		dirAddr = found
	}

	// Level 2: find name/ID
	if level >= 2 {
		found, isDir := findResourceEntry(ctx.Mem, dirAddr, rsrcBase, uint32(resName))
		if found == 0 {
			// If name lookup fails and name is a string pointer, try first entry
			found, isDir = findResourceFirstEntry(ctx.Mem, dirAddr, rsrcBase)
			if found == 0 {
				return 0xC0000089 // STATUS_RESOURCE_NAME_NOT_FOUND
			}
		}
		if !isDir {
			ctx.Mem.Write64(entryPtr, found)
			return StatusSuccess
		}
		dirAddr = found
	}

	// Level 3: find language (pick best match or first)
	if level >= 3 {
		var found uint64
		if resLang != 0 {
			found, _ = findResourceEntry(ctx.Mem, dirAddr, rsrcBase, uint32(resLang))
		}
		if found == 0 {
			// Try neutral (0x0000) or English
			found = pickBestResourceLang(ctx.Mem, dirAddr, rsrcBase)
		}
		if found == 0 {
			return 0xC000008A // STATUS_RESOURCE_LANG_NOT_FOUND
		}
		ctx.Mem.Write64(entryPtr, found)
		return StatusSuccess
	}

	return 0xC000008A
}

// handleLdrAccessResource returns the address and size of a resource data entry.
// LdrAccessResource(HMODULE hModule, IMAGE_RESOURCE_DATA_ENTRY *entry, void **ptr, ULONG *size)
func handleLdrAccessResource(ctx *TrapContext) uint32 {
	hModule := ctx.Arg(0)
	entryAddr := ctx.Arg(1)
	ptrOut := ctx.Arg(2)
	sizeOut := ctx.Arg(3)

	if hModule == 0 || entryAddr == 0 {
		return 0xC0000135
	}

	// IMAGE_RESOURCE_DATA_ENTRY: OffsetToData(4), Size(4), CodePage(4), Reserved(4)
	dataRVA, _ := ctx.Mem.Read32(entryAddr)
	dataSize, _ := ctx.Mem.Read32(entryAddr + 4)

	dataAddr := hModule + uint64(dataRVA)

	if ptrOut != 0 {
		ctx.Mem.Write64(ptrOut, dataAddr)
	}
	if sizeOut != 0 {
		ctx.Mem.Write32(sizeOut, dataSize)
	}

	return StatusSuccess
}

// peResourceDir reads the resource directory RVA and size from PE headers in guest memory.
func peResourceDir(mem *mmu.MMU, baseAddr uint64) (rva, size uint32) {
	// Check MZ signature
	mz, _ := mem.Read16(baseAddr)
	if mz != 0x5A4D {
		return 0, 0
	}
	// e_lfanew at offset 0x3C
	lfanew, _ := mem.Read32(baseAddr + 0x3C)
	peAddr := baseAddr + uint64(lfanew)
	// Check PE signature
	peSig, _ := mem.Read32(peAddr)
	if peSig != 0x00004550 {
		return 0, 0
	}
	// Optional header starts at PE+24
	// For PE32+ (64-bit), data directories start at optional header + 0x70
	// Resource table is directory entry 2 (each entry = 8 bytes)
	optHdr := peAddr + 24
	rva, _ = mem.Read32(optHdr + 0x70 + 2*8)     // resource dir RVA
	size, _ = mem.Read32(optHdr + 0x70 + 2*8 + 4) // resource dir size
	return rva, size
}

// findResourceEntry searches a resource directory for an entry with the given ID.
func findResourceEntry(mem *mmu.MMU, dirAddr, rsrcBase uint64, id uint32) (addr uint64, isDir bool) {
	numNamed, _ := mem.Read16(dirAddr + 12)
	numID, _ := mem.Read16(dirAddr + 14)
	total := int(numNamed) + int(numID)
	entryBase := dirAddr + 16

	for i := 0; i < total; i++ {
		eid, _ := mem.Read32(entryBase + uint64(i)*8)
		off, _ := mem.Read32(entryBase + uint64(i)*8 + 4)
		if eid == id {
			isSubDir := off&0x80000000 != 0
			return rsrcBase + uint64(off&0x7FFFFFFF), isSubDir
		}
	}
	return 0, false
}

// findResourceFirstEntry returns the first entry in a resource directory.
func findResourceFirstEntry(mem *mmu.MMU, dirAddr, rsrcBase uint64) (addr uint64, isDir bool) {
	numNamed, _ := mem.Read16(dirAddr + 12)
	numID, _ := mem.Read16(dirAddr + 14)
	total := int(numNamed) + int(numID)
	if total == 0 {
		return 0, false
	}
	off, _ := mem.Read32(dirAddr + 16 + 4) // first entry's offset
	isSubDir := off&0x80000000 != 0
	return rsrcBase + uint64(off&0x7FFFFFFF), isSubDir
}

// pickBestResourceLang picks the best language entry: neutral (0), English (0x09), or first.
func pickBestResourceLang(mem *mmu.MMU, dirAddr, rsrcBase uint64) uint64 {
	numNamed, _ := mem.Read16(dirAddr + 12)
	numID, _ := mem.Read16(dirAddr + 14)
	total := int(numNamed) + int(numID)
	if total == 0 {
		return 0
	}
	entryBase := dirAddr + 16
	var fallback uint64
	for i := 0; i < total; i++ {
		langID, _ := mem.Read32(entryBase + uint64(i)*8)
		off, _ := mem.Read32(entryBase + uint64(i)*8 + 4)
		addr := rsrcBase + uint64(off&0x7FFFFFFF)
		if i == 0 {
			fallback = addr
		}
		if langID == 0x0000 || langID&0xFF == 0x09 {
			return addr
		}
	}
	return fallback
}

// handleVsnprintf implements _vsnprintf(buf, count, fmt, args).
// We do a minimal implementation that reads the format string and copies it without formatting.
func handleVsnprintf(ctx *TrapContext) uint32 {
	buf := ctx.Arg(0)
	count := ctx.Arg(1)
	fmtAddr := ctx.Arg(2)

	if buf == 0 || count == 0 || fmtAddr == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}

	// Read format string
	var fmtBytes []byte
	for i := uint64(0); i < 4096; i++ {
		b, _ := ctx.Mem.Read8(fmtAddr + i)
		if b == 0 {
			break
		}
		fmtBytes = append(fmtBytes, b)
	}

	// Simple: just copy format string as-is (no substitution)
	// This is enough for Wine debug output which uses it for logging
	n := uint64(len(fmtBytes))
	if n >= count {
		n = count - 1
	}
	for i := uint64(0); i < n; i++ {
		ctx.Mem.Write8(buf+i, fmtBytes[i])
	}
	ctx.Mem.Write8(buf+n, 0)
	ctx.SetReturn(n)
	return StatusSuccess
}

// handleVsnwprintf implements _vsnwprintf(buf, count, fmt, args).
func handleVsnwprintf(ctx *TrapContext) uint32 {
	buf := ctx.Arg(0)
	count := ctx.Arg(1)
	fmtAddr := ctx.Arg(2)

	if buf == 0 || count == 0 || fmtAddr == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}

	// Read wide format string
	var fmtChars []uint16
	for i := uint64(0); i < 4096; i++ {
		ch, _ := ctx.Mem.Read16(fmtAddr + i*2)
		if ch == 0 {
			break
		}
		fmtChars = append(fmtChars, ch)
	}

	n := uint64(len(fmtChars))
	if n >= count {
		n = count - 1
	}
	for i := uint64(0); i < n; i++ {
		ctx.Mem.Write16(buf+i*2, fmtChars[i])
	}
	ctx.Mem.Write16(buf+n*2, 0)
	ctx.SetReturn(n)
	return StatusSuccess
}

// handleRtlFindClearBitsAndSet finds 'count' contiguous clear bits in a bitmap,
// sets them, and returns the starting index (or 0xFFFFFFFF if not found).
func handleRtlFindClearBitsAndSet(ctx *TrapContext) uint32 {
	bitmapAddr := ctx.Arg(0)
	numBits := uint32(ctx.Arg(1))
	hintIdx := uint32(ctx.Arg(2))

	if bitmapAddr == 0 || numBits == 0 {
		ctx.SetReturn(0xFFFFFFFF)
		return StatusSuccess
	}

	// RTL_BITMAP: { ULONG SizeOfBitMap; PULONG Buffer; }
	sizeOfBitMap, _ := ctx.Mem.Read32(bitmapAddr)
	bufferAddr, _ := ctx.Mem.Read64(bitmapAddr + 8)

	if bufferAddr == 0 || sizeOfBitMap == 0 {
		ctx.SetReturn(0xFFFFFFFF)
		return StatusSuccess
	}

	// Search for numBits contiguous clear bits starting from hintIdx
	for start := hintIdx; start+numBits <= sizeOfBitMap; start++ {
		found := true
		for bit := uint32(0); bit < numBits; bit++ {
			idx := start + bit
			wordIdx := idx / 32
			bitIdx := idx % 32
			word, _ := ctx.Mem.Read32(bufferAddr + uint64(wordIdx)*4)
			if word&(1<<bitIdx) != 0 {
				found = false
				start = start + bit // skip ahead
				break
			}
		}
		if found {
			// Set the bits
			for bit := uint32(0); bit < numBits; bit++ {
				idx := start + bit
				wordIdx := idx / 32
				bitIdx := idx % 32
				addr := bufferAddr + uint64(wordIdx)*4
				word, _ := ctx.Mem.Read32(addr)
				word |= 1 << bitIdx
				ctx.Mem.Write32(addr, word)
			}
			ctx.SetReturn(uint64(start))
			return StatusSuccess
		}
	}
	// Wrap around from 0 if hint was > 0
	if hintIdx > 0 {
		for start := uint32(0); start+numBits <= hintIdx; start++ {
			found := true
			for bit := uint32(0); bit < numBits; bit++ {
				idx := start + bit
				wordIdx := idx / 32
				bitIdx := idx % 32
				word, _ := ctx.Mem.Read32(bufferAddr + uint64(wordIdx)*4)
				if word&(1<<bitIdx) != 0 {
					found = false
					start = start + bit
					break
				}
			}
			if found {
				for bit := uint32(0); bit < numBits; bit++ {
					idx := start + bit
					wordIdx := idx / 32
					bitIdx := idx % 32
					addr := bufferAddr + uint64(wordIdx)*4
					word, _ := ctx.Mem.Read32(addr)
					word |= 1 << bitIdx
					ctx.Mem.Write32(addr, word)
				}
				ctx.SetReturn(uint64(start))
				return StatusSuccess
			}
		}
	}

	ctx.SetReturn(0xFFFFFFFF)
	return StatusSuccess
}

// handleLdrQueryImageFileExecutionOptions is a stub - returns not found.
func handleLdrQueryImageFileExecutionOptions(ctx *TrapContext) uint32 {
	ctx.SetReturn(uint64(StatusObjectNameNotFound))
	return StatusObjectNameNotFound
}

// handleRtlReleasePath frees a path returned by LdrGetDllPath.
func handleRtlReleasePath(ctx *TrapContext) uint32 {
	return StatusSuccess
}

// handleNtUserInitializeClientPfnArrays registers user32's client-side callback table.
func handleNtUserInitializeClientPfnArrays(ctx *TrapContext) uint32 {
	ctx.SetReturn(0)
	return StatusSuccess
}

// handleNtUserGetSystemDpiForProcess returns the system DPI.
func handleNtUserGetSystemDpiForProcess(ctx *TrapContext) uint32 {
	ctx.SetReturn(96) // standard DPI
	return StatusSuccess
}

// ======================== ATOM TABLE ========================

var atomCounter uint32 = 0xC000 // Start from 0xC000 (application atoms)
var atomTable = map[string]uint32{}

func handleNtAddAtom(ctx *TrapContext) uint32 {
namePtr := ctx.Arg(0)
nameLen := ctx.Arg(1) // length in bytes
atomPtr := ctx.Arg(2) // output RTL_ATOM*

name := ""
if namePtr != 0 && nameLen > 0 {
name = readGuestStringUTF16(ctx.Mem, namePtr, int(nameLen))
}

atom, ok := atomTable[name]
if !ok {
atom = atomCounter
atomCounter++
atomTable[name] = atom
}

if atomPtr != 0 {
ctx.Mem.Write16(atomPtr, uint16(atom))
}
return StatusSuccess
}

func handleNtDeleteAtom(ctx *TrapContext) uint32 {
return StatusSuccess
}

func handleNtFindAtom(ctx *TrapContext) uint32 {
namePtr := ctx.Arg(0)
nameLen := ctx.Arg(1)
atomPtr := ctx.Arg(2)

name := ""
if namePtr != 0 && nameLen > 0 {
name = readGuestStringUTF16(ctx.Mem, namePtr, int(nameLen))
}

atom, ok := atomTable[name]
if !ok {
return StatusObjectNameNotFound
}

if atomPtr != 0 {
ctx.Mem.Write16(atomPtr, uint16(atom))
}
return StatusSuccess
}

func handleNtQueryInformationAtom(ctx *TrapContext) uint32 {
return StatusNotImplemented
}

// ======================== NtUserCallOneParam / NtUserCallTwoParam ========================

func handleNtUserCallOneParam(ctx *TrapContext) uint32 {
param := ctx.Arg(0)
code := ctx.Arg(1) // function code

if ctx.Trace {
	fmt.Printf("  NtUserCallOneParam: code=%d param=0x%x\n", code, param)
}

switch code {
case 11: // ONEPARAM_ROUTINE_GETSYSTEMMETRICS
	ctx.SetReturn(getSystemMetric(uint32(param)))
case 21: // ONEPARAM_ROUTINE_SETCARETBLINKTIME
	ctx.SetReturn(1) // TRUE
case 26: // ONEPARAM_ROUTINE_SETPROCESSDEFAULTLAYOUT
	ctx.SetReturn(1)
case 28: // ONEPARAM_ROUTINE_CREATEEMPTYCURSOROBJECT
	h := ctx.Handles.Alloc(&GenericHandle{Kind: "cursor"})
	ctx.SetReturn(uint64(h))
case 37: // ONEPARAM_ROUTINE_GETDPIFORMONITOR
	ctx.SetReturn(96) // 96 DPI
case 73: // ONEPARAM_ROUTINE_RELEASEDC
	ctx.SetReturn(1)
default:
	ctx.SetReturn(0)
}
return StatusSuccess
}

func getSystemMetric(index uint32) uint64 {
	switch index {
	case 0: // SM_CXSCREEN
		return 1920
	case 1: // SM_CYSCREEN
		return 1080
	case 2: // SM_CXVSCROLL
		return 17
	case 3: // SM_CYHSCROLL
		return 17
	case 4: // SM_CYCAPTION
		return 23
	case 5: // SM_CXBORDER
		return 1
	case 6: // SM_CYBORDER
		return 1
	case 7: // SM_CXDLGFRAME / SM_CXFIXEDFRAME
		return 3
	case 8: // SM_CYDLGFRAME / SM_CYFIXEDFRAME
		return 3
	case 11: // SM_CXHTHUMB
		return 17
	case 12: // SM_CYICON
		return 32
	case 13: // SM_CXCURSOR (also SM_CXICON)
		return 32
	case 14: // SM_CYCURSOR
		return 32
	case 15: // SM_CYMENU
		return 20
	case 16: // SM_CXFULLSCREEN
		return 1920
	case 17: // SM_CYFULLSCREEN
		return 1017 // 1080 - caption - menu
	case 18: // SM_CYKANJIWINDOW
		return 0
	case 20: // SM_CXHSCROLL
		return 17
	case 21: // SM_CYVSCROLL
		return 17
	case 22: // SM_CXMIN
		return 136
	case 23: // SM_CYMIN
		return 39
	case 24: // SM_CXSIZE
		return 36
	case 25: // SM_CYSIZE
		return 36
	case 26: // SM_CXFRAME / SM_CXSIZEFRAME
		return 4
	case 27: // SM_CYFRAME / SM_CYSIZEFRAME
		return 4
	case 28: // SM_CXMINTRACK
		return 136
	case 29: // SM_CYMINTRACK
		return 39
	case 30: // SM_CXDOUBLECLK
		return 4
	case 31: // SM_CYDOUBLECLK
		return 4
	case 32: // SM_CXICONSPACING
		return 75
	case 33: // SM_CYICONSPACING
		return 75
	case 34: // SM_MENUDROPALIGNMENT
		return 0
	case 36: // SM_CXDRAG
		return 4
	case 37: // SM_CYDRAG
		return 4
	case 43: // SM_SWAPBUTTON
		return 0
	case 45: // SM_CXEDGE (SM_CXBORDER*2)
		return 2
	case 46: // SM_CYEDGE (SM_CYBORDER*2)
		return 2
	case 47: // SM_CXMINSPACING
		return 160
	case 48: // SM_CYMINSPACING
		return 24
	case 49: // SM_CXSMICON
		return 16
	case 50: // SM_CYSMICON
		return 16
	case 51: // SM_CYSMCAPTION
		return 23
	case 52: // SM_CXSMSIZE
		return 12
	case 53: // SM_CYSMSIZE
		return 14
	case 54: // SM_CXMENUSIZE
		return 18
	case 55: // SM_CYMENUSIZE
		return 18
	case 67: // SM_IMMENABLED
		return 0
	case 70: // SM_CMETRICS
		return 76
	case 75: // SM_CXFOCUSBORDER
		return 1
	case 76: // SM_CYFOCUSBORDER
		return 1
	case 78: // SM_CXPADDEDBORDER
		return 4
	case 80: // SM_DIGITIZER
		return 0
	default:
		return 0
	}
}

func handleNtUserCallTwoParam(ctx *TrapContext) uint32 {
//param1 := ctx.Arg(0)
//param2 := ctx.Arg(1)
//code := ctx.Arg(2)
ctx.SetReturn(0) // generic success
return StatusSuccess
}

// ---- SList (Singly-Linked List) operations ----
// SLIST_HEADER is 16 bytes: { NextEntry uint64; Depth uint16; CpuId uint16; pad uint32 }

func handleRtlInitializeSListHead(ctx *TrapContext) uint32 {
	head := ctx.Arg(0)
	if head != 0 {
		ctx.Mem.Write64(head, 0)   // NextEntry = NULL
		ctx.Mem.Write64(head+8, 0) // Depth=0, CpuId=0
	}
	return StatusSuccess
}

func handleRtlInterlockedFlushSList(ctx *TrapContext) uint32 {
	head := ctx.Arg(0)
	if head == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	first, _ := ctx.Mem.Read64(head)
	ctx.Mem.Write64(head, 0)   // clear list
	ctx.Mem.Write64(head+8, 0) // depth=0
	ctx.SetReturn(first)
	return StatusSuccess
}

func handleRtlInterlockedPopEntrySList(ctx *TrapContext) uint32 {
	head := ctx.Arg(0)
	if head == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	first, _ := ctx.Mem.Read64(head)
	if first == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	next, _ := ctx.Mem.Read64(first) // SLIST_ENTRY.Next
	ctx.Mem.Write64(head, next)
	// Decrement depth
	depthWord, _ := ctx.Mem.Read16(head + 8)
	if depthWord > 0 {
		ctx.Mem.Write16(head+8, depthWord-1)
	}
	ctx.SetReturn(first)
	return StatusSuccess
}

func handleRtlInterlockedPushEntrySList(ctx *TrapContext) uint32 {
	head := ctx.Arg(0)
	entry := ctx.Arg(1)
	if head == 0 || entry == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	oldFirst, _ := ctx.Mem.Read64(head)
	ctx.Mem.Write64(entry, oldFirst) // entry->Next = old first
	ctx.Mem.Write64(head, entry)     // head->NextEntry = entry
	// Increment depth
	depthWord, _ := ctx.Mem.Read16(head + 8)
	ctx.Mem.Write16(head+8, depthWord+1)
	ctx.SetReturn(oldFirst)
	return StatusSuccess
}

func handleRtlQueryDepthSList(ctx *TrapContext) uint32 {
	head := ctx.Arg(0)
	if head == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	depth, _ := ctx.Mem.Read16(head + 8)
	ctx.SetReturn(uint64(depth))
	return StatusSuccess
}

// ---- Performance Counter ----

var perfFreq uint64 = 1_000_000_000 // 1GHz (nanosecond resolution)

func handleRtlQueryPerformanceCounter(ctx *TrapContext) uint32 {
	out := ctx.Arg(0) // LARGE_INTEGER*
	if out != 0 {
		ctx.Mem.Write64(out, uint64(time.Now().UnixNano()))
	}
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlQueryPerformanceFrequency(ctx *TrapContext) uint32 {
	out := ctx.Arg(0) // LARGE_INTEGER*
	if out != 0 {
		ctx.Mem.Write64(out, perfFreq)
	}
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

// ---- Misc ----

func handleRtlRandom(ctx *TrapContext) uint32 {
	seedPtr := ctx.Arg(0) // ULONG*
	var seed uint32
	if seedPtr != 0 {
		v, _ := ctx.Mem.Read32(seedPtr)
		seed = v
	}
	// Simple LCG
	seed = seed*214013 + 2531011
	if seedPtr != 0 {
		ctx.Mem.Write32(seedPtr, seed)
	}
	ctx.SetReturn(uint64(seed >> 16 & 0x7FFF))
	return StatusSuccess
}

func handleWineGetHostVersion(ctx *TrapContext) uint32 {
	// wine_get_host_version(const char **sysname, const char **release)
	sysname := ctx.Arg(0)
	release := ctx.Arg(1)
	if sysname != 0 {
		buf := ctx.Mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
		for i, b := range []byte("Linux") {
			ctx.Mem.Write8(buf+uint64(i), b)
		}
		ctx.Mem.Write8(buf+5, 0)
		ctx.Mem.Write64(sysname, buf)
	}
	if release != 0 {
		buf := ctx.Mem.Mmap(0, 16, mmu.PermRead|mmu.PermWrite)
		for i, b := range []byte("6.1.0") {
			ctx.Mem.Write8(buf+uint64(i), b)
		}
		ctx.Mem.Write8(buf+5, 0)
		ctx.Mem.Write64(release, buf)
	}
	return StatusSuccess
}

// ======================== NtGdi* - GDI Object Stubs ========================

// GDI object type codes (for GdiSharedHandleTable entry+0x0E).
const (
	gdiObjDC     = 0x01
	gdiObjBrush  = 0x02
	gdiObjPen    = 0x03
	gdiObjPal    = 0x05
	gdiObjFont   = 0x06
	gdiObjBitmap = 0x07
	gdiObjRegion = 0x08
)

const gdiEntrySize = 24

// allocGdiHandle allocates a handle and writes a corresponding entry in the
// GDI shared handle table so gdi32 user-mode code can validate it.
func allocGdiHandle(ctx *TrapContext, kind string, objType byte) Handle {
	h := ctx.Handles.Alloc(&GenericHandle{Kind: kind})
	idx := uint64(h) & 0xFFFF
	if ctx.State.GdiTableAddr != 0 && idx < 0x4000 {
		entry := ctx.State.GdiTableAddr + idx*gdiEntrySize
		ctx.Mem.Write8(entry+0x0E, objType)
	}
	return h
}

func handleNtGdiCreateBitmap(ctx *TrapContext) uint32 {
	// NtGdiCreateBitmap(width, height, planes, bpp, bits)
	w := ctx.Arg(0)
	h := ctx.Arg(1)
	if ctx.Trace {
		fmt.Printf("  NtGdiCreateBitmap: %dx%d planes=%d bpp=%d\n", w, h, ctx.Arg(2), ctx.Arg(3))
	}
	handle := allocGdiHandle(ctx, "bitmap", gdiObjBitmap)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiCreatePatternBrushInternal(ctx *TrapContext) uint32 {
	bitmapHandle := ctx.Arg(0)
	if ctx.Trace {
		fmt.Printf("  NtGdiCreatePatternBrushInternal: bitmap=0x%x\n", bitmapHandle)
	}
	handle := allocGdiHandle(ctx, "brush", gdiObjBrush)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiDeleteObjectApp(ctx *TrapContext) uint32 {
	h := Handle(ctx.Arg(0))
	// Clear GDI table entry
	idx := uint64(h) & 0xFFFF
	if ctx.State.GdiTableAddr != 0 && idx < 0x4000 {
		entry := ctx.State.GdiTableAddr + idx*gdiEntrySize
		ctx.Mem.Write8(entry+0x0E, 0)
	}
	ctx.Handles.Close(h)
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleNtGdiSelectBitmap(ctx *TrapContext) uint32 {
	// Returns previous bitmap handle (fake)
	ctx.SetReturn(ctx.Arg(1)) // return the bitmap being selected
	return StatusSuccess
}

func handleNtGdiSelectBrush(ctx *TrapContext) uint32 {
	ctx.SetReturn(ctx.Arg(1))
	return StatusSuccess
}

func handleNtGdiSelectPen(ctx *TrapContext) uint32 {
	ctx.SetReturn(ctx.Arg(1))
	return StatusSuccess
}

func handleNtGdiSelectFont(ctx *TrapContext) uint32 {
	ctx.SetReturn(ctx.Arg(1))
	return StatusSuccess
}

func handleNtGdiCreateSolidBrush(ctx *TrapContext) uint32 {
	handle := allocGdiHandle(ctx, "brush", gdiObjBrush)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiCreatePen(ctx *TrapContext) uint32 {
	handle := allocGdiHandle(ctx, "pen", gdiObjPen)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiCreateRectRgn(ctx *TrapContext) uint32 {
	handle := allocGdiHandle(ctx, "region", gdiObjRegion)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiCreateCompatibleDC(ctx *TrapContext) uint32 {
	handle := allocGdiHandle(ctx, "dc", gdiObjDC)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiCreateCompatibleBitmap(ctx *TrapContext) uint32 {
	handle := allocGdiHandle(ctx, "bitmap", gdiObjBitmap)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiHfontCreate(ctx *TrapContext) uint32 {
	handle := allocGdiHandle(ctx, "font", gdiObjFont)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiExtGetObjectW(ctx *TrapContext) uint32 {
	// Returns the size of data written (0 = error, but return 1 for basic compat)
	ctx.SetReturn(0)
	return StatusSuccess
}

func handleNtGdiGetDeviceCaps(ctx *TrapContext) uint32 {
	index := ctx.Arg(1)
	var val uint64
	switch index {
	case 8: // HORZRES
		val = 1920
	case 10: // VERTRES
		val = 1080
	case 12: // BITSPIXEL
		val = 32
	case 14: // PLANES
		val = 1
	case 88: // LOGPIXELSX
		val = 96
	case 90: // LOGPIXELSY
		val = 96
	case 118: // DESKTOPHORZRES
		val = 1920
	case 117: // DESKTOPVERTRES
		val = 1080
	default:
		val = 0
	}
	ctx.SetReturn(val)
	return StatusSuccess
}

func handleNtGdiGetAndSetDCDword(ctx *TrapContext) uint32 {
	resultPtr := ctx.Arg(3)
	if resultPtr != 0 {
		ctx.Mem.Write32(resultPtr, 0)
	}
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleNtGdiSaveDC(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // Save level 1
	return StatusSuccess
}

func handleNtGdiRestoreDC(ctx *TrapContext) uint32 {
	ctx.SetReturn(1)
	return StatusSuccess
}

func handleNtGdiCombineRgn(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // NULLREGION
	return StatusSuccess
}

func handleNtGdiGetRgnBox(ctx *TrapContext) uint32 {
	rectPtr := ctx.Arg(1)
	if rectPtr != 0 {
		ctx.Mem.Write32(rectPtr, 0)    // left
		ctx.Mem.Write32(rectPtr+4, 0)  // top
		ctx.Mem.Write32(rectPtr+8, 0)  // right
		ctx.Mem.Write32(rectPtr+12, 0) // bottom
	}
	ctx.SetReturn(1) // NULLREGION
	return StatusSuccess
}

func handleNtGdiSetRectRgn(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleNtGdiOffsetRgn(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // NULLREGION
	return StatusSuccess
}

func handleNtGdiPatBlt(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleNtGdiBitBlt(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleNtGdiOpenDCW(ctx *TrapContext) uint32 {
	handle := allocGdiHandle(ctx, "dc", gdiObjDC)
	ctx.SetReturn(uint64(handle))
	return StatusSuccess
}

func handleNtGdiGetTextMetricsW(ctx *TrapContext) uint32 {
	tmPtr := ctx.Arg(1)
	if tmPtr != 0 {
		// Fill TEXTMETRICW with reasonable defaults (60 bytes)
		for i := uint64(0); i < 60; i += 4 {
			ctx.Mem.Write32(tmPtr+i, 0)
		}
		ctx.Mem.Write32(tmPtr+0, 16)  // tmHeight
		ctx.Mem.Write32(tmPtr+4, 12)  // tmAscent
		ctx.Mem.Write32(tmPtr+8, 4)   // tmDescent
		ctx.Mem.Write32(tmPtr+20, 8)  // tmAveCharWidth
		ctx.Mem.Write32(tmPtr+24, 16) // tmMaxCharWidth
	}
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleNtGdiFlush(ctx *TrapContext) uint32 {
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

// ======================== CRT HANDLERS (complex, trap-based) ========================

func handleStrtol(ctx *TrapContext) uint32 {
	strAddr := ctx.Arg(0)
	endptrAddr := ctx.Arg(1)
	base := ctx.Arg(2)

	s := readCString(ctx.Mem, strAddr, 64)
	val, _ := strconvParseInt(s, int(base))
	ctx.CPU.SetSyscallReturn(uint64(val))
	ctx.ReturnOverridden = true
	if endptrAddr != 0 {
		ctx.Mem.Write64(endptrAddr, strAddr+uint64(len(s)))
	}
	return 0
}

func handleWcstol(ctx *TrapContext) uint32 {
	strAddr := ctx.Arg(0)
	endptrAddr := ctx.Arg(1)
	base := ctx.Arg(2)

	s := readWideString(ctx.Mem, strAddr, 64)
	val, _ := strconvParseInt(s, int(base))
	ctx.CPU.SetSyscallReturn(uint64(val))
	ctx.ReturnOverridden = true
	if endptrAddr != 0 {
		ctx.Mem.Write64(endptrAddr, strAddr+uint64(len(s)*2))
	}
	return 0
}

func handleWcstoul(ctx *TrapContext) uint32 {
	strAddr := ctx.Arg(0)
	endptrAddr := ctx.Arg(1)
	base := ctx.Arg(2)

	s := readWideString(ctx.Mem, strAddr, 64)
	val, _ := strconvParseUint(s, int(base))
	ctx.CPU.SetSyscallReturn(val)
	ctx.ReturnOverridden = true
	if endptrAddr != 0 {
		ctx.Mem.Write64(endptrAddr, strAddr+uint64(len(s)*2))
	}
	return 0
}

func handleStrnicmp(ctx *TrapContext) uint32 {
	s1Addr := ctx.Arg(0)
	s2Addr := ctx.Arg(1)
	n := ctx.Arg(2)

	for i := uint64(0); i < n; i++ {
		c1, _ := ctx.Mem.Read8(s1Addr + i)
		c2, _ := ctx.Mem.Read8(s2Addr + i)
		if c1 == 0 && c2 == 0 {
			return 0
		}
		l1, l2 := toLowerByte(c1), toLowerByte(c2)
		if l1 != l2 {
			if l1 < l2 {
				ctx.CPU.SetSyscallReturn(^uint64(0)) // -1
			} else {
				ctx.CPU.SetSyscallReturn(1)
			}
			ctx.ReturnOverridden = true
			return 0
		}
		if c1 == 0 {
			return 0
		}
	}
	return 0
}

func handleWcsicmp(ctx *TrapContext) uint32 {
	s1Addr := ctx.Arg(0)
	s2Addr := ctx.Arg(1)

	for i := uint64(0); ; i += 2 {
		c1, _ := ctx.Mem.Read16(s1Addr + i)
		c2, _ := ctx.Mem.Read16(s2Addr + i)
		l1, l2 := toLowerWide(c1), toLowerWide(c2)
		if l1 != l2 {
			if l1 < l2 {
				ctx.CPU.SetSyscallReturn(^uint64(0))
			} else {
				ctx.CPU.SetSyscallReturn(1)
			}
			ctx.ReturnOverridden = true
			return 0
		}
		if c1 == 0 {
			return 0
		}
	}
}

func handleWcsnicmp(ctx *TrapContext) uint32 {
	s1Addr := ctx.Arg(0)
	s2Addr := ctx.Arg(1)
	n := ctx.Arg(2)

	for i := uint64(0); i < n; i++ {
		c1, _ := ctx.Mem.Read16(s1Addr + i*2)
		c2, _ := ctx.Mem.Read16(s2Addr + i*2)
		l1, l2 := toLowerWide(c1), toLowerWide(c2)
		if l1 != l2 {
			if l1 < l2 {
				ctx.CPU.SetSyscallReturn(^uint64(0))
			} else {
				ctx.CPU.SetSyscallReturn(1)
			}
			ctx.ReturnOverridden = true
			return 0
		}
		if c1 == 0 {
			return 0
		}
	}
	return 0
}

func handleIsalpha(ctx *TrapContext) uint32 {
	c := byte(ctx.Arg(0))
	if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
		ctx.CPU.SetSyscallReturn(1)
		ctx.ReturnOverridden = true
	}
	return 0
}

func handleIslower(ctx *TrapContext) uint32 {
	c := byte(ctx.Arg(0))
	if c >= 'a' && c <= 'z' {
		ctx.CPU.SetSyscallReturn(1)
		ctx.ReturnOverridden = true
	}
	return 0
}

func handleIsxdigit(ctx *TrapContext) uint32 {
	c := byte(ctx.Arg(0))
	if (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f') {
		ctx.CPU.SetSyscallReturn(1)
		ctx.ReturnOverridden = true
	}
	return 0
}

func handleStrpbrk(ctx *TrapContext) uint32 {
	strAddr := ctx.Arg(0)
	charsAddr := ctx.Arg(1)

	accept := readCString(ctx.Mem, charsAddr, 256)
	acceptSet := make(map[byte]bool)
	for _, c := range []byte(accept) {
		acceptSet[c] = true
	}

	for i := uint64(0); ; i++ {
		c, _ := ctx.Mem.Read8(strAddr + i)
		if c == 0 {
			break
		}
		if acceptSet[c] {
			ctx.CPU.SetSyscallReturn(strAddr + i)
			ctx.ReturnOverridden = true
			return 0
		}
	}
	ctx.CPU.SetSyscallReturn(0)
	ctx.ReturnOverridden = true
	return 0
}

func handleWcspbrk(ctx *TrapContext) uint32 {
	strAddr := ctx.Arg(0)
	charsAddr := ctx.Arg(1)

	acceptSet := make(map[uint16]bool)
	for i := uint64(0); ; i += 2 {
		c, _ := ctx.Mem.Read16(charsAddr + i)
		if c == 0 {
			break
		}
		acceptSet[c] = true
	}

	for i := uint64(0); ; i += 2 {
		c, _ := ctx.Mem.Read16(strAddr + i)
		if c == 0 {
			break
		}
		if acceptSet[c] {
			ctx.CPU.SetSyscallReturn(strAddr + i)
			ctx.ReturnOverridden = true
			return 0
		}
	}
	ctx.CPU.SetSyscallReturn(0)
	ctx.ReturnOverridden = true
	return 0
}

func handleWcscspn(ctx *TrapContext) uint32 {
	strAddr := ctx.Arg(0)
	rejectAddr := ctx.Arg(1)

	rejectSet := make(map[uint16]bool)
	for i := uint64(0); ; i += 2 {
		c, _ := ctx.Mem.Read16(rejectAddr + i)
		if c == 0 {
			break
		}
		rejectSet[c] = true
	}

	count := uint64(0)
	for i := uint64(0); ; i += 2 {
		c, _ := ctx.Mem.Read16(strAddr + i)
		if c == 0 || rejectSet[c] {
			break
		}
		count++
	}
	ctx.CPU.SetSyscallReturn(count)
	ctx.ReturnOverridden = true
	return 0
}

func handleWcsspn(ctx *TrapContext) uint32 {
	strAddr := ctx.Arg(0)
	acceptAddr := ctx.Arg(1)

	acceptSet := make(map[uint16]bool)
	for i := uint64(0); ; i += 2 {
		c, _ := ctx.Mem.Read16(acceptAddr + i)
		if c == 0 {
			break
		}
		acceptSet[c] = true
	}

	count := uint64(0)
	for i := uint64(0); ; i += 2 {
		c, _ := ctx.Mem.Read16(strAddr + i)
		if c == 0 || !acceptSet[c] {
			break
		}
		count++
	}
	ctx.CPU.SetSyscallReturn(count)
	ctx.ReturnOverridden = true
	return 0
}

func handleWcsstr(ctx *TrapContext) uint32 {
	haystackAddr := ctx.Arg(0)
	needleAddr := ctx.Arg(1)

	needle := readWideChars(ctx.Mem, needleAddr, 256)
	if len(needle) == 0 {
		ctx.CPU.SetSyscallReturn(haystackAddr)
		ctx.ReturnOverridden = true
		return 0
	}

	for i := uint64(0); ; i += 2 {
		c, _ := ctx.Mem.Read16(haystackAddr + i)
		if c == 0 {
			break
		}
		if c == needle[0] {
			match := true
			for j := 1; j < len(needle); j++ {
				h, _ := ctx.Mem.Read16(haystackAddr + i + uint64(j*2))
				if h != needle[j] {
					match = false
					break
				}
			}
			if match {
				ctx.CPU.SetSyscallReturn(haystackAddr + i)
				ctx.ReturnOverridden = true
				return 0
			}
		}
	}
	ctx.CPU.SetSyscallReturn(0)
	ctx.ReturnOverridden = true
	return 0
}

// helpers

func toLowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 0x20
	}
	return c
}

func toLowerWide(c uint16) uint16 {
	if c >= 'A' && c <= 'Z' {
		return c + 0x20
	}
	return c
}

func readWideChars(mem *mmu.MMU, addr uint64, maxChars int) []uint16 {
	var result []uint16
	for i := 0; i < maxChars; i++ {
		c, err := mem.Read16(addr + uint64(i*2))
		if err != nil || c == 0 {
			break
		}
		result = append(result, c)
	}
	return result
}

func readWideString(mem *mmu.MMU, addr uint64, maxChars int) string {
	chars := readWideChars(mem, addr, maxChars)
	buf := make([]byte, 0, len(chars))
	for _, c := range chars {
		if c < 128 {
			buf = append(buf, byte(c))
		} else {
			buf = append(buf, '?')
		}
	}
	return string(buf)
}

func readCString(mem *mmu.MMU, addr uint64, maxLen int) string {
	var buf []byte
	for i := 0; i < maxLen; i++ {
		b, err := mem.Read8(addr + uint64(i))
		if err != nil || b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

func strconvParseInt(s string, base int) (int64, error) {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	if i >= len(s) {
		return 0, nil
	}
	neg := false
	if s[i] == '-' {
		neg = true
		i++
	} else if s[i] == '+' {
		i++
	}
	if base == 0 {
		if i+1 < len(s) && s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X') {
			base = 16
			i += 2
		} else if i < len(s) && s[i] == '0' {
			base = 8
			i++
		} else {
			base = 10
		}
	}
	var val int64
	for i < len(s) {
		c := s[i]
		var digit int64
		if c >= '0' && c <= '9' {
			digit = int64(c - '0')
		} else if c >= 'a' && c <= 'f' {
			digit = int64(c-'a') + 10
		} else if c >= 'A' && c <= 'F' {
			digit = int64(c-'A') + 10
		} else {
			break
		}
		if digit >= int64(base) {
			break
		}
		val = val*int64(base) + digit
		i++
	}
	if neg {
		val = -val
	}
	return val, nil
}

func strconvParseUint(s string, base int) (uint64, error) {
	v, err := strconvParseInt(s, base)
	return uint64(v), err
}

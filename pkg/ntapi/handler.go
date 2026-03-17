//go:build guest_windows

package ntapi

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/mirkobrombin/Raven/pkg/mmu"

	ravelog "github.com/mirkobrombin/Raven/pkg/log"
	"golang.org/x/sys/unix"
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
	StatusObjectNameCollision  uint32 = 0xC0000035
	StatusKeyNotFound          uint32 = 0xC0000225
	StatusPending              uint32 = 0x00000103
	StatusTimeout              uint32 = 0x00000102
	StatusWait0                uint32 = 0x00000000
	StatusAlerted              uint32 = 0x00000101
	StatusProcessIsTerminating uint32 = 0xC000010A
	StatusEndOfFile            uint32 = 0xC0000011
)

// File access and creation flags.
const (
	fileSupersede   = 0x00000000
	fileOpen        = 0x00000001
	fileCreate      = 0x00000002
	fileOpenIf      = 0x00000003
	fileOverwrite   = 0x00000004
	fileOverwriteIf = 0x00000005

	fileDirectoryFile         = 0x00000001
	fileNonDirectoryFile      = 0x00000040
	fileSynchronousIoNonalert = 0x00000020
)

// FileInformationClass values.
const (
	fileDirectoryInformation     = 1
	fileBasicInformation         = 4
	fileStandardInformation      = 5
	fileNameInformation          = 9
	filePositionInformation      = 14
	fileDispositionInformation   = 13
	fileBothDirectoryInformation = 3
	fileEndOfFileInformation     = 20
	fileAllInformation           = 18
)

// ======================== FILE I/O ========================

const (
	dupCloseSource = 0x00000001
	dupSameAccess  = 0x00000002

	memCommit   = 0x00001000
	memReserve  = 0x00002000
	memDecommit = 0x00004000
	memRelease  = 0x00008000

	secCommit = 0x08000000
)

type ntDirEntry struct {
	Name  string
	IsDir bool
	Size  int64
	Atime time.Time
	Mtime time.Time
	Ctime time.Time
	Nlink uint32
}

func writeGuestPtr(mem *mmu.MMU, addr, val uint64) {
	if addr == 0 {
		return
	}
	if mem.Mode32 {
		mem.Write32(addr, uint32(val))
		return
	}
	mem.Write64(addr, val)
}

func signalHandleEvent(ctx *TrapContext, eventHandle Handle) {
	if eventHandle == 0 {
		return
	}
	if eh := ctx.Handles.GetEvent(eventHandle); eh != nil {
		eh.Set()
	}
}

func ntStatusFromErr(err error, notFound uint32) uint32 {
	if err == nil {
		return StatusSuccess
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "not found"), strings.Contains(msg, "no such"):
		return notFound
	case strings.Contains(msg, "exist"), strings.Contains(msg, "collision"):
		return StatusObjectNameCollision
	case strings.Contains(msg, "directory"):
		return StatusAccessDenied
	default:
		return StatusAccessDenied
	}
}

func desiredAccessToOpenFlags(desiredAccess uint32) int {
	const (
		genericRead   = 0x80000000
		genericWrite  = 0x40000000
		fileReadData  = 0x0001
		fileWriteData = 0x0002
		fileAppend    = 0x0004
	)
	canRead := desiredAccess&genericRead != 0 || desiredAccess&fileReadData != 0
	canWrite := desiredAccess&genericWrite != 0 || desiredAccess&(fileWriteData|fileAppend) != 0
	switch {
	case canRead && canWrite:
		return os.O_RDWR
	case canWrite:
		return os.O_WRONLY
	default:
		return os.O_RDONLY
	}
}

func getFileOffset(ctx *TrapContext, fh *FileHandle) uint64 {
	if fh == nil {
		return 0
	}
	fd := ctx.FS.GetFD(fh.FD)
	if fd != nil {
		return uint64(fd.Offset)
	}
	off, err := ctx.FS.Lseek(fh.FD, 0, 1)
	if err != nil || off < 0 {
		return 0
	}
	return uint64(off)
}

func wildcardMatch(pattern, name string) bool {
	pattern = strings.ToLower(pattern)
	name = strings.ToLower(name)
	var match func(pi, ni int) bool
	match = func(pi, ni int) bool {
		for pi < len(pattern) {
			switch pattern[pi] {
			case '*':
				for pi+1 < len(pattern) && pattern[pi+1] == '*' {
					pi++
				}
				if pi+1 == len(pattern) {
					return true
				}
				for i := ni; i <= len(name); i++ {
					if match(pi+1, i) {
						return true
					}
				}
				return false
			case '?':
				if ni >= len(name) {
					return false
				}
				pi++
				ni++
			default:
				if ni >= len(name) || pattern[pi] != name[ni] {
					return false
				}
				pi++
				ni++
			}
		}
		return ni == len(name)
	}
	if pattern == "" {
		return true
	}
	if pattern == "*.*" {
		return true
	}
	return match(0, 0)
}

func listDirectoryEntries(ctx *TrapContext, fh *FileHandle) []ntDirEntry {
	if fh == nil {
		return nil
	}
	if dirNode := ctx.FS.Stat(fh.FD); dirNode != nil && dirNode.IsDir && len(dirNode.Children) > 0 {
		names := make([]string, 0, len(dirNode.Children))
		for name := range dirNode.Children {
			names = append(names, name)
		}
		sort.Strings(names)
		out := make([]ntDirEntry, 0, len(names))
		for _, name := range names {
			child := dirNode.Children[name]
			out = append(out, ntDirEntry{
				Name:  child.Name,
				IsDir: child.IsDir,
				Size:  child.Size,
				Atime: child.Atime,
				Mtime: child.Mtime,
				Ctime: child.Ctime,
				Nlink: child.Nlink,
			})
		}
		return out
	}

	hostEntries, err := os.ReadDir(fh.Path)
	if err != nil {
		return nil
	}
	sort.Slice(hostEntries, func(i, j int) bool {
		return strings.ToLower(hostEntries[i].Name()) < strings.ToLower(hostEntries[j].Name())
	})
	out := make([]ntDirEntry, 0, len(hostEntries))
	for _, entry := range hostEntries {
		info, ierr := entry.Info()
		if ierr != nil {
			continue
		}
		out = append(out, ntDirEntry{
			Name:  entry.Name(),
			IsDir: entry.IsDir(),
			Size:  info.Size(),
			Atime: info.ModTime(),
			Mtime: info.ModTime(),
			Ctime: info.ModTime(),
			Nlink: 1,
		})
	}
	return out
}

func closeHandleObject(ctx *TrapContext, handle Handle, obj HandleObject) {
	switch v := obj.(type) {
	case *FileHandle:
		if v.DeletePending && v.Path != "" {
			_ = ctx.FS.Unlinkat(-1, v.Path, 0)
		}
		_ = ctx.FS.Close(v.FD)
	case *SectionHandle:
		if v.FileFD >= 0 {
			_ = ctx.FS.Close(v.FileFD)
		}
	}
	_ = handle
}

func cloneHandleObject(ctx *TrapContext, obj HandleObject) (HandleObject, uint32) {
	switch v := obj.(type) {
	case *FileHandle:
		newFD, err := ctx.FS.Dup(v.FD)
		if err != nil {
			return nil, StatusInvalidHandle
		}
		cp := *v
		cp.FD = newFD
		return &cp, StatusSuccess
	case *SectionHandle:
		cp := *v
		if v.FileFD >= 0 {
			newFD, err := ctx.FS.Dup(v.FileFD)
			if err != nil {
				return nil, StatusInvalidHandle
			}
			cp.FileFD = newFD
		}
		if v.ViewSizes != nil {
			cp.ViewSizes = make(map[uint64]uint64, len(v.ViewSizes))
			for k, val := range v.ViewSizes {
				cp.ViewSizes[k] = val
			}
		}
		return &cp, StatusSuccess
	default:
		return obj, StatusSuccess
	}
}

func handleNtCreateFile(ctx *TrapContext) uint32 {
	// NtCreateFile(FileHandle*, DesiredAccess, ObjectAttributes*, IoStatusBlock*,
	//              AllocationSize*, FileAttributes, ShareAccess, CreateDisposition,
	//              CreateOptions, EaBuffer*, EaLength)
	handlePtr := ctx.Arg(0)
	desiredAccess := uint32(ctx.Arg(1))
	objAttr := ctx.Arg(2)
	ioStatus := ctx.Arg(3)
	createDisp := uint32(ctx.Arg(7))
	createOpts := uint32(ctx.Arg(8))

	rootDir, _, attrs, err := ReadObjectAttributes(ctx, objAttr)
	path, err := ResolveObjectPath(ctx, objAttr)
	if err != nil || path == "" {
		writeIOStatus(ctx.Mem, ioStatus, StatusObjectPathNotFound, 0)
		return StatusObjectPathNotFound
	}
	if ctx.Trace {
		fmt.Printf("  NtCreateFile: path=%q root=0x%x attrs=0x%x access=0x%x disp=%d opts=0x%x\n", path, rootDir, attrs, desiredAccess, createDisp, createOpts)
	}

	isDir := createOpts&fileDirectoryFile != 0
	baseFlags := desiredAccessToOpenFlags(desiredAccess)
	fileInfo := uint64(1)

	_, statErr := ctx.FS.StatPath(-100, path)
	exists := statErr == nil
	if createDisp == fileCreate && exists {
		writeIOStatus(ctx.Mem, ioStatus, StatusObjectNameCollision, 0)
		return StatusObjectNameCollision
	}
	if createDisp == fileOpen && !exists {
		writeIOStatus(ctx.Mem, ioStatus, StatusObjectNameNotFound, 0)
		return StatusObjectNameNotFound
	}

	flags := baseFlags
	switch createDisp {
	case fileCreate, fileOpenIf:
		flags |= os.O_CREATE
	case fileOverwrite, fileOverwriteIf, fileSupersede:
		flags |= os.O_CREATE | os.O_TRUNC
	}
	if desiredAccess&0x0004 != 0 {
		flags |= os.O_APPEND
	}

	if isDir {
		if createDisp == fileCreate || createDisp == fileOpenIf || createDisp == fileOverwriteIf || createDisp == fileSupersede {
			ctx.FS.MkdirAll(path)
			fileInfo = 2
		}
	} else {
		switch createDisp {
		case fileCreate:
			fileInfo = 2
		case fileOpenIf:
			if !exists {
				fileInfo = 2
			}
		case fileOverwrite, fileOverwriteIf:
			fileInfo = 3
		case fileSupersede:
			fileInfo = 4
		}
	}

	fd, openErr := ctx.FS.OpenAt(-100, path, flags, 0644)
	if openErr != nil {
		status := ntStatusFromErr(openErr, StatusObjectNameNotFound)
		writeIOStatus(ctx.Mem, ioStatus, status, 0)
		return status
	}

	fh := &FileHandle{FD: fd, Path: path, Access: desiredAccess}
	h := ctx.Handles.Alloc(fh)
	writeGuestPtr(ctx.Mem, handlePtr, uint64(h))
	writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, fileInfo)
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
	bufAddr := ctx.Arg(5)
	length := ctx.Arg(6)
	pByteOffset := ctx.Arg(7)
	// Arg(8) = Key (ignored)

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		if pipe := ctx.Handles.GetNamedPipe(fileHandle); pipe != nil {
			data := make([]byte, length)
			n := pipe.PipeRead(data)
			status := uint32(StatusSuccess)
			if n == 0 && length > 0 {
				status = StatusEndOfFile
			}
			if n > 0 {
				ctx.Mem.WriteBytes(bufAddr, data[:n])
			}
			writeIOStatus(ctx.Mem, ioStatus, status, uint64(n))
			signalHandleEvent(ctx, eventHandle)
			return status
		}
	}
	if fh == nil {
		writeIOStatus(ctx.Mem, ioStatus, StatusInvalidHandle, 0)
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
				status = StatusEndOfFile
			}
			if n > 0 {
				ctx.Mem.WriteBytes(bufAddr, buf[:n])
			}
			writeIOStatus(ctx.Mem, ioStatus, status, uint64(n))
			signalHandleEvent(ctx, eventHandle)
			return status
		}
	}

	buf := make([]byte, length)
	n, err := ctx.FS.Read(fh.FD, buf)
	status := uint32(StatusSuccess)
	if n == 0 && err != nil {
		status = StatusEndOfFile
	}

	if n > 0 {
		ctx.Mem.WriteBytes(bufAddr, buf[:n])
	}

	writeIOStatus(ctx.Mem, ioStatus, status, uint64(n))
	signalHandleEvent(ctx, eventHandle)

	return status
}

func handleNtWriteFile(ctx *TrapContext) uint32 {
	// NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock*, Buffer, Length, ByteOffset*, Key*)
	// ReactOS reference: ntoskrnl/io/iomgr/iofunc.c NtWriteFile
	fileHandle := Handle(ctx.Arg(0))
	eventHandle := Handle(ctx.Arg(1))
	// Arg(2) = ApcRoutine (ignored)
	// Arg(3) = ApcContext (ignored)
	ioStatus := ctx.Arg(4)
	bufAddr := ctx.Arg(5)
	length := ctx.Arg(6)
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
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, length)
		return StatusSuccess
	}

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		if pipe := ctx.Handles.GetNamedPipe(fileHandle); pipe != nil {
			data, err := ctx.Mem.ReadBytes(bufAddr, int(length))
			if err != nil {
				return StatusInvalidParameter
			}
			if pByteOffset != 0 {
				offset, _ := ctx.Mem.Read64(pByteOffset)
				_ = offset
			}
			if !pipe.PipeWrite(data) {
				return StatusAccessDenied
			}
			writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, length)
			signalHandleEvent(ctx, eventHandle)
			return StatusSuccess
		}
	}
	if fh == nil {
		writeIOStatus(ctx.Mem, ioStatus, StatusInvalidHandle, 0)
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
			writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, uint64(n))
			signalHandleEvent(ctx, eventHandle)
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

	writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, uint64(n))
	signalHandleEvent(ctx, eventHandle)

	return StatusSuccess
}

func handleNtClose(ctx *TrapContext) uint32 {
	handle := Handle(ctx.Arg(0))
	obj := ctx.Handles.Get(handle)
	if obj == nil {
		return StatusInvalidHandle
	}
	closeHandleObject(ctx, handle, obj)
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
	infoClass := uint32(ctx.Arg(4))

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		writeIOStatus(ctx.Mem, ioStatus, StatusInvalidHandle, 0)
		return StatusInvalidHandle
	}

	node := ctx.FS.Stat(fh.FD)
	if node == nil {
		writeIOStatus(ctx.Mem, ioStatus, StatusNoSuchFile, 0)
		return StatusNoSuchFile
	}

	attrs := uint32(0x80)
	if node.IsDir {
		attrs = 0x10
	}
	createFT := windowsFileTime(node.Ctime)
	accessFT := windowsFileTime(node.Atime)
	writeFT := windowsFileTime(node.Mtime)
	changeFT := windowsFileTime(node.Ctime)
	eof := uint64(node.Size)
	alloc := (eof + mmu.PageSize - 1) & mmu.PageMask
	if eof == 0 {
		alloc = 0
	}
	winPath := `\??\` + VFSToNtPath(fh.Path)
	nameBytes := encodeUTF16LE(winPath)
	position := getFileOffset(ctx, fh)

	switch infoClass {
	case fileBasicInformation:
		if length < 40 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		ctx.Mem.Write64(buffer+0, createFT)
		ctx.Mem.Write64(buffer+8, accessFT)
		ctx.Mem.Write64(buffer+16, writeFT)
		ctx.Mem.Write64(buffer+24, changeFT)
		ctx.Mem.Write32(buffer+32, attrs)
		ctx.Mem.Write32(buffer+36, 0)
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 40)
		return StatusSuccess
	case fileStandardInformation:
		if length < 24 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		ctx.Mem.Write64(buffer+0, alloc)
		ctx.Mem.Write64(buffer+8, eof)
		ctx.Mem.Write32(buffer+16, node.Nlink)
		ctx.Mem.Write8(buffer+20, boolToByte(fh.DeletePending))
		ctx.Mem.Write8(buffer+21, boolToByte(node.IsDir))
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 24)
		return StatusSuccess
	case fileNameInformation:
		needed := uint64(4 + len(nameBytes))
		if length < 4 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		ctx.Mem.Write32(buffer+0, uint32(len(nameBytes)))
		toCopy := minUint32(uint32(len(nameBytes)), uint32(length-4))
		if toCopy > 0 {
			ctx.Mem.WriteBytes(buffer+4, nameBytes[:toCopy])
		}
		if length < needed {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferOverflow, length)
			return StatusBufferOverflow
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, needed)
		return StatusSuccess
	case filePositionInformation:
		if length < 8 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		ctx.Mem.Write64(buffer, position)
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 8)
		return StatusSuccess
	case fileEndOfFileInformation:
		if length < 8 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		ctx.Mem.Write64(buffer, eof)
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 8)
		return StatusSuccess
	case fileAllInformation:
		needed := uint64(96 + 4 + len(nameBytes))
		if length < 96 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		ctx.Mem.Write64(buffer+0, createFT)
		ctx.Mem.Write64(buffer+8, accessFT)
		ctx.Mem.Write64(buffer+16, writeFT)
		ctx.Mem.Write64(buffer+24, changeFT)
		ctx.Mem.Write32(buffer+32, attrs)
		ctx.Mem.Write32(buffer+36, 0)
		ctx.Mem.Write64(buffer+40, alloc)
		ctx.Mem.Write64(buffer+48, eof)
		ctx.Mem.Write32(buffer+56, node.Nlink)
		ctx.Mem.Write8(buffer+60, boolToByte(fh.DeletePending))
		ctx.Mem.Write8(buffer+61, boolToByte(node.IsDir))
		ctx.Mem.Write32(buffer+76, fh.Access)
		ctx.Mem.Write64(buffer+80, position)
		ctx.Mem.Write32(buffer+88, 0)
		ctx.Mem.Write32(buffer+92, 0)
		ctx.Mem.Write32(buffer+96, uint32(len(nameBytes)))
		avail := uint32(0)
		if length > 100 {
			avail = uint32(length - 100)
		}
		toCopy := minUint32(uint32(len(nameBytes)), avail)
		if toCopy > 0 {
			ctx.Mem.WriteBytes(buffer+100, nameBytes[:toCopy])
		}
		if length < needed {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferOverflow, length)
			return StatusBufferOverflow
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, needed)
		return StatusSuccess
	default:
		writeIOStatus(ctx.Mem, ioStatus, StatusNotImplemented, 0)
		return StatusNotImplemented
	}
}

func handleNtSetInformationFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	ioStatus := ctx.Arg(1)
	buffer := ctx.Arg(2)
	length := uint32(ctx.Arg(3))
	class := uint32(ctx.Arg(4))

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		writeIOStatus(ctx.Mem, ioStatus, StatusInvalidHandle, 0)
		return StatusInvalidHandle
	}

	switch class {
	case fileDispositionInformation:
		deleteFile := false
		if buffer != 0 {
			flag, _ := ctx.Mem.Read8(buffer)
			deleteFile = flag != 0
		}
		fh.DeletePending = deleteFile
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 0)
		return StatusSuccess
	case filePositionInformation:
		pos, _ := ctx.Mem.Read64(buffer)
		if _, err := ctx.FS.Lseek(fh.FD, int64(pos), 0); err != nil {
			writeIOStatus(ctx.Mem, ioStatus, StatusInvalidParameter, 0)
			return StatusInvalidParameter
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 0)
		return StatusSuccess
	case fileEndOfFileInformation, 19:
		eof, _ := ctx.Mem.Read64(buffer)
		if err := ctx.FS.Ftruncate(fh.FD, int64(eof)); err != nil {
			status := ntStatusFromErr(err, StatusInvalidParameter)
			writeIOStatus(ctx.Mem, ioStatus, status, 0)
			return status
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 0)
		return StatusSuccess
	case 10:
		var replaceIfExists bool
		var rootDir Handle
		var nameLen uint32
		var nameAddr uint64
		if ctx.Mem.Mode32 {
			flag, _ := ctx.Mem.Read8(buffer)
			replaceIfExists = flag != 0
			rootVal, _ := ctx.Mem.Read32(buffer + 4)
			rootDir = Handle(rootVal)
			nameLen, _ = ctx.Mem.Read32(buffer + 8)
			nameAddr = buffer + 12
		} else {
			flag, _ := ctx.Mem.Read8(buffer)
			replaceIfExists = flag != 0
			rootVal, _ := ctx.Mem.Read64(buffer + 8)
			rootDir = Handle(rootVal)
			nameLen, _ = ctx.Mem.Read32(buffer + 16)
			nameAddr = buffer + 20
		}
		if nameLen == 0 || length < nameLen {
			writeIOStatus(ctx.Mem, ioStatus, StatusInvalidParameter, 0)
			return StatusInvalidParameter
		}
		nameBytes, err := ctx.Mem.ReadBytes(nameAddr, int(nameLen))
		if err != nil {
			writeIOStatus(ctx.Mem, ioStatus, StatusInvalidParameter, 0)
			return StatusInvalidParameter
		}
		newName := decodeUTF16LE(nameBytes)
		newPath := NtPathToVFS(newName)
		if !(strings.HasPrefix(newName, `\`) || (len(newName) >= 2 && newName[1] == ':')) {
			basePath := fh.Path
			if rootDir != 0 {
				if base := ctx.Handles.GetFile(rootDir); base != nil {
					basePath = base.Path
				}
			} else if slash := strings.LastIndex(basePath, "/"); slash >= 0 {
				basePath = basePath[:slash]
				if basePath == "" {
					basePath = "/"
				}
			}
			if !strings.HasPrefix(newPath, "/") {
				newPath = "/" + newPath
			}
			if basePath == "/" {
				newPath = basePath + strings.TrimPrefix(newPath, "/")
			} else {
				newPath = basePath + newPath
			}
		}
		if replaceIfExists {
			_ = ctx.FS.Unlinkat(-1, newPath, 0)
		}
		if err := ctx.FS.Renameat(-1, fh.Path, -1, newPath); err != nil {
			status := ntStatusFromErr(err, StatusObjectNameNotFound)
			writeIOStatus(ctx.Mem, ioStatus, status, 0)
			return status
		}
		fh.Path = newPath
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 0)
		return StatusSuccess
	default:
		writeIOStatus(ctx.Mem, ioStatus, StatusNotImplemented, 0)
		return StatusNotImplemented
	}
}

func decodeUTF16(chars []uint16) []rune {
	var out []rune
	for i := 0; i < len(chars); i++ {
		if chars[i] >= 0xD800 && chars[i] <= 0xDBFF && i+1 < len(chars) {
			hi := rune(chars[i]) - 0xD800
			lo := rune(chars[i+1]) - 0xDC00
			out = append(out, 0x10000+hi<<10+lo)
			i++
		} else {
			out = append(out, rune(chars[i]))
		}
	}
	return out
}

func handleNtQueryDirectoryFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	eventHandle := Handle(ctx.Arg(1))
	ioStatus := ctx.Arg(4)
	buffer := ctx.Arg(5)
	length := ctx.Arg(6)
	infoClass := uint32(ctx.Arg(7))
	returnSingleEntry := ctx.Arg(8) != 0
	fileNamePtr := ctx.Arg(9)
	restartScan := ctx.Arg(10) != 0

	fh := ctx.Handles.GetFile(fileHandle)
	if fh == nil {
		writeIOStatus(ctx.Mem, ioStatus, StatusInvalidHandle, 0)
		return StatusInvalidHandle
	}
	if restartScan {
		fh.DirIndex = 0
	}
	if fileNamePtr != 0 {
		mask, err := ReadUnicodeString(ctx.Mem, fileNamePtr)
		if err == nil {
			fh.DirMask = mask
		}
	}

	allEntries := listDirectoryEntries(ctx, fh)
	if len(allEntries) == 0 {
		writeIOStatus(ctx.Mem, ioStatus, StatusNoMoreFiles, 0)
		return StatusNoMoreFiles
	}

	matches := make([]ntDirEntry, 0, len(allEntries))
	for _, entry := range allEntries {
		if fh.DirMask == "" || wildcardMatch(fh.DirMask, entry.Name) {
			matches = append(matches, entry)
		}
	}
	if fh.DirIndex >= len(matches) {
		writeIOStatus(ctx.Mem, ioStatus, StatusNoMoreFiles, 0)
		return StatusNoMoreFiles
	}

	offset := uint64(0)
	prevOffset := uint64(0)
	prevSize := uint64(0)
	written := 0
	for idx := fh.DirIndex; idx < len(matches); idx++ {
		entry := matches[idx]
		nameUTF16 := encodeUTF16LE(entry.Name)
		baseSize := uint64(64)
		nameOffset := uint64(64)
		if infoClass == fileBothDirectoryInformation {
			baseSize = 94
			nameOffset = 94
		} else if infoClass != fileDirectoryInformation {
			writeIOStatus(ctx.Mem, ioStatus, StatusNotImplemented, 0)
			return StatusNotImplemented
		}
		entrySize := (baseSize + uint64(len(nameUTF16)) + 7) &^ uint64(7)
		if offset+entrySize > length {
			break
		}
		addr := buffer + offset
		if written > 0 {
			ctx.Mem.Write32(buffer+prevOffset, uint32(prevSize))
		}
		createFT := windowsFileTime(entry.Ctime)
		accessFT := windowsFileTime(entry.Atime)
		writeFT := windowsFileTime(entry.Mtime)
		changeFT := windowsFileTime(entry.Ctime)
		attrs := uint32(0x80)
		if entry.IsDir {
			attrs = 0x10
		}
		ctx.Mem.Write32(addr+0, 0)
		ctx.Mem.Write32(addr+4, uint32(idx))
		ctx.Mem.Write64(addr+8, createFT)
		ctx.Mem.Write64(addr+16, accessFT)
		ctx.Mem.Write64(addr+24, writeFT)
		ctx.Mem.Write64(addr+32, changeFT)
		ctx.Mem.Write64(addr+40, uint64(entry.Size))
		ctx.Mem.Write64(addr+48, uint64(entry.Size))
		ctx.Mem.Write32(addr+56, attrs)
		ctx.Mem.Write32(addr+60, uint32(len(nameUTF16)))
		if infoClass == fileBothDirectoryInformation {
			ctx.Mem.Write32(addr+64, 0)
			ctx.Mem.Write8(addr+68, 0)
			ctx.Mem.Write8(addr+69, 0)
		}
		ctx.Mem.WriteBytes(addr+nameOffset, nameUTF16)
		prevOffset = offset
		prevSize = entrySize
		offset += entrySize
		written++
		fh.DirIndex = idx + 1
		if returnSingleEntry {
			break
		}
	}
	if written == 0 {
		writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
		return StatusBufferTooSmall
	}
	ctx.Mem.Write32(buffer+prevOffset, 0)
	writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, offset)
	signalHandleEvent(ctx, eventHandle)
	return StatusSuccess
}

func handleNtQueryVolumeInformationFile(ctx *TrapContext) uint32 {
	_ = Handle(ctx.Arg(0)) // FileHandle
	ioStatus := ctx.Arg(1)
	buffer := ctx.Arg(2)
	length := uint32(ctx.Arg(3))
	class := uint32(ctx.Arg(4))

	switch class {
	case 1: // FileFsVolumeInformation
		label := "Raven"
		labelUTF16 := encodeUTF16LE(label)
		needed := uint32(18 + len(labelUTF16))
		if length < needed {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferOverflow, 0)
			return StatusBufferOverflow
		}
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0)                          // VolumeCreationTime
			ctx.Mem.Write32(buffer+8, 0x12345678)               // VolumeSerialNumber
			ctx.Mem.Write32(buffer+12, uint32(len(labelUTF16))) // VolumeLabelLength
			ctx.Mem.Write8(buffer+16, 0)                        // SupportsObjects (BOOLEAN)
			ctx.Mem.Write8(buffer+17, 0)                        // padding
			ctx.Mem.WriteBytes(buffer+18, labelUTF16)           // VolumeLabel
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, uint64(needed))

	case 3: // FileFsSizeInformation
		if length < 24 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 1000000)  // TotalAllocationUnits
			ctx.Mem.Write64(buffer+8, 500000) // AvailableAllocationUnits
			ctx.Mem.Write32(buffer+16, 8)     // SectorsPerAllocationUnit
			ctx.Mem.Write32(buffer+20, 512)   // BytesPerSector
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 24)

	case 4: // FileFsDeviceInformation
		if length < 8 {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferTooSmall, 0)
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 7)   // DeviceType (FILE_DEVICE_DISK)
			ctx.Mem.Write32(buffer+4, 0) // Characteristics
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 8)

	case 5: // FileFsAttributeInformation
		fsName := "NTFS"
		fsNameUTF16 := encodeUTF16LE(fsName)
		needed := uint32(12 + len(fsNameUTF16))
		if length < needed {
			writeIOStatus(ctx.Mem, ioStatus, StatusBufferOverflow, 0)
			return StatusBufferOverflow
		}
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0x00000003)                 // FileSystemAttributes (CASE_PRESERVED|CASE_SENSITIVE)
			ctx.Mem.Write32(buffer+4, 255)                      // MaximumComponentNameLength
			ctx.Mem.Write32(buffer+8, uint32(len(fsNameUTF16))) // FileSystemNameLength
			ctx.Mem.WriteBytes(buffer+12, fsNameUTF16)          // FileSystemName
		}
		writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, uint64(needed))

	default:
		return StatusNotImplemented
	}

	return StatusSuccess
}

func handleNtDeleteFile(ctx *TrapContext) uint32 {
	// NtDeleteFile(POBJECT_ATTRIBUTES ObjectAttributes)
	objAttr := ctx.Arg(0)
	path, err := ResolveObjectPath(ctx, objAttr)
	if err != nil || path == "" {
		return StatusObjectPathNotFound
	}
	vfsPath := path
	if strings.TrimSpace(vfsPath) == "" {
		return StatusObjectPathNotFound
	}
	if err := ctx.FS.Unlinkat(-1, vfsPath, 0); err != nil {
		msg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(msg, "not found"), strings.Contains(msg, "no such"):
			return StatusObjectNameNotFound
		case strings.Contains(msg, "is a directory"), strings.Contains(msg, "not a directory"):
			return StatusAccessDenied
		case strings.Contains(msg, "directory not empty"):
			return StatusAccessDenied
		default:
			return StatusAccessDenied
		}
	}
	return StatusSuccess
}

func handleNtFlushBuffersFile(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtDeviceIoControlFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	_ = ctx.Arg(1) // Event
	_ = ctx.Arg(2) // ApcRoutine
	_ = ctx.Arg(3) // ApcContext
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
		writeIOStatus(ctx.Mem, ioStatus, 0xC0000010, 0) // STATUS_INVALID_DEVICE_REQUEST
		return 0xC0000010
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
	sectionProtect := uint32(ctx.Arg(4))
	allocationAttrs := uint32(ctx.Arg(5))
	fileHandle := Handle(ctx.Arg(6))

	var maxSize uint64
	if maxSizePtr != 0 {
		maxSize, _ = ctx.Mem.Read64(maxSizePtr)
	}

	perms := NtMemProtectToMMU(sectionProtect)
	if perms == 0 {
		perms = mmu.PermRead | mmu.PermWrite
	}

	sec := &SectionHandle{
		Perms:     perms,
		FileFD:    -1,
		ViewSizes: make(map[uint64]uint64),
	}
	if fh := ctx.Handles.GetFile(fileHandle); fh != nil {
		if maxSize == 0 {
			if node := ctx.FS.Stat(fh.FD); node != nil {
				maxSize = uint64(node.Size)
			}
		}
		if dupFD, err := ctx.FS.Dup(fh.FD); err == nil {
			sec.FileFD = dupFD
		}
		sec.Path = fh.Path
	}
	if maxSize == 0 && allocationAttrs&secCommit != 0 {
		maxSize = mmu.PageSize
	}
	if maxSize == 0 {
		maxSize = mmu.PageSize
	}
	sec.Size = (maxSize + mmu.PageSize - 1) & mmu.PageMask

	h := ctx.Handles.Alloc(sec)
	writeGuestPtr(ctx.Mem, handlePtr, uint64(h))

	return StatusSuccess
}

func handleNtMapViewOfSection(ctx *TrapContext) uint32 {
	sectionHandle := Handle(ctx.Arg(0))
	_ = ctx.Arg(1) // ProcessHandle
	baseAddrPtr := ctx.Arg(2)
	_ = ctx.Arg(3) // ZeroBits
	_ = ctx.Arg(4) // CommitSize
	sectionOffsetPtr := ctx.Arg(5)
	viewSizePtr := ctx.Arg(6)
	_ = ctx.Arg(7) // InheritDisposition
	_ = ctx.Arg(8) // AllocationType
	win32Protect := uint32(ctx.Arg(9))

	sec := ctx.Handles.GetSection(sectionHandle)
	if sec == nil {
		return StatusInvalidHandle
	}

	baseAddr := uint64(0)
	if baseAddrPtr != 0 {
		baseAddr, _ = ctx.Mem.Read64(baseAddrPtr)
	}
	sectionOffset := uint64(0)
	if sectionOffsetPtr != 0 {
		sectionOffset, _ = ctx.Mem.Read64(sectionOffsetPtr)
	}
	size := sec.Size
	if viewSizePtr != 0 {
		if requested, _ := ctx.Mem.Read64(viewSizePtr); requested != 0 {
			size = requested
		}
	}
	if size == 0 {
		size = mmu.PageSize
	}
	size = (size + mmu.PageSize - 1) & mmu.PageMask
	perms := sec.Perms
	if win32Protect != 0 {
		perms = NtMemProtectToMMU(win32Protect)
	}

	addr := ctx.Mem.Mmap(baseAddr, size, perms)
	if sec.FileFD >= 0 {
		buf := make([]byte, size)
		if n, err := ctx.FS.Pread(sec.FileFD, buf, int64(sectionOffset)); err == nil && n > 0 {
			ctx.Mem.WriteBytes(addr, buf[:n])
		}
	}
	sec.ViewSizes[addr] = size
	if baseAddrPtr != 0 {
		ctx.Mem.Write64(baseAddrPtr, addr)
	}
	if viewSizePtr != 0 {
		ctx.Mem.Write64(viewSizePtr, size)
	}

	return StatusSuccess
}

func handleNtUnmapViewOfSection(ctx *TrapContext) uint32 {
	_ = ctx.Arg(0) // ProcessHandle
	baseAddr := ctx.Arg(1)

	if baseAddr != 0 {
		_, size, mapped, _ := ctx.Mem.QueryRegion(baseAddr)
		if mapped && size > 0 {
			ctx.Mem.Munmap(baseAddr, size)
		}
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

	h := ctx.Handles.Alloc(&RegistryKeyHandle{Key: key, Path: name})
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
	h := ctx.Handles.Alloc(&RegistryKeyHandle{Key: key, Path: name})
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
		ctx.Mem.Write32(buffer+0, 0)                     // TitleIndex
		ctx.Mem.Write32(buffer+4, val.Type)              // Type
		ctx.Mem.Write32(buffer+8, uint32(len(val.Data))) // DataLength
		ctx.Mem.WriteBytes(buffer+12, val.Data)          // Data
	}

	return StatusSuccess
}

func handleNtSetValueKey(ctx *TrapContext) uint32 {
	keyHandle := Handle(ctx.Arg(0))
	valueNameAddr := ctx.Arg(1)
	_ = ctx.Arg(2) // TitleIndex
	valType := uint32(ctx.Arg(3))
	dataAddr := ctx.Arg(4)
	dataSize := uint32(ctx.Arg(5))

	rk := ctx.Handles.GetRegKey(keyHandle)
	if rk == nil {
		return StatusInvalidHandle
	}

	valueName, err := ReadUnicodeString(ctx.Mem, valueNameAddr)
	if err != nil {
		return StatusObjectNameInvalid
	}

	// Stack args: DataPtr and DataSize
	var data []byte
	if dataAddr != 0 && dataSize > 0 {
		if raw, err := ctx.Mem.ReadBytes(dataAddr, int(dataSize)); err == nil {
			data = append([]byte(nil), raw...)
		}
	}
	rk.Key.Values[valueName] = &RegistryValue{
		Name: valueName,
		Type: valType,
		Data: data,
	}

	return StatusSuccess
}

func handleNtDeleteKey(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleNtDeleteValueKey(ctx *TrapContext) uint32 {
	keyHandle := Handle(ctx.Arg(0))
	valueNameAddr := ctx.Arg(1)
	rk := ctx.Handles.GetRegKey(keyHandle)
	if rk == nil {
		return StatusInvalidHandle
	}
	valueName, err := ReadUnicodeString(ctx.Mem, valueNameAddr)
	if err != nil {
		return StatusObjectNameInvalid
	}
	delete(rk.Key.Values, valueName)
	for k := range rk.Key.Values {
		if strings.EqualFold(k, valueName) {
			delete(rk.Key.Values, k)
			break
		}
	}
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
		ctx.Mem.Write64(buffer+0, 0)                       // LastWriteTime
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
		ctx.Mem.Write32(buffer+0, 0)                      // TitleIndex
		ctx.Mem.Write32(buffer+4, val.Type)               // Type
		ctx.Mem.Write32(buffer+8, uint32(len(nameUTF16))) // NameLength
		ctx.Mem.WriteBytes(buffer+12, nameUTF16)
	}

	return StatusSuccess
}

func handleNtQueryKey(ctx *TrapContext) uint32 {
	keyHandle := Handle(ctx.Arg(0))
	infoClass := uint32(ctx.Arg(1))
	buffer := ctx.Arg(2)
	length := uint32(ctx.Arg(3))
	retLen := ctx.Arg(4)

	rk := ctx.Handles.GetRegKey(keyHandle)
	if rk == nil {
		return StatusInvalidHandle
	}

	keyName := rk.Path
	if keyName == "" && rk.Key != nil {
		keyName = rk.Key.Name
	}
	nameUTF16 := encodeUTF16LE(keyName)

	switch infoClass {
	case 0: // KeyBasicInformation
		needed := uint32(16 + len(nameUTF16))
		if retLen != 0 {
			ctx.Mem.Write32(retLen, needed)
		}
		if length < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write64(buffer+0, 0)
			ctx.Mem.Write32(buffer+8, 0)
			ctx.Mem.Write32(buffer+12, uint32(len(nameUTF16)))
			ctx.Mem.WriteBytes(buffer+16, nameUTF16)
		}
		return StatusSuccess
	case 1: // KeyNodeInformation
		valueCount := uint32(len(rk.Key.Values))
		subKeyCount := uint32(len(rk.Key.Children))
		needed := uint32(28 + len(nameUTF16))
		if retLen != 0 {
			ctx.Mem.Write32(retLen, needed)
		}
		if length < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write64(buffer+0, 0)
			ctx.Mem.Write32(buffer+8, 0)
			ctx.Mem.Write32(buffer+12, uint32(len(nameUTF16)))
			ctx.Mem.Write32(buffer+16, subKeyCount)
			ctx.Mem.Write32(buffer+20, valueCount)
			ctx.Mem.Write32(buffer+24, 0)
			ctx.Mem.WriteBytes(buffer+28, nameUTF16)
		}
		return StatusSuccess
	default:
		return StatusNotImplemented
	}
}

// ======================== PROCESS / THREAD ========================

func handleNtQueryInformationProcess(ctx *TrapContext) uint32 {
	// NtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation, ProcessInformationLength, ReturnLength)
	infoClass := uint32(ctx.Arg(1))
	buffer := ctx.Arg(2)
	bufLen := uint32(ctx.Arg(3))
	retLen := ctx.Arg(4)

	writeRetLen := func(n uint32) {
		if retLen != 0 {
			ctx.Mem.Write32(retLen, n)
		}
	}

	switch infoClass {
	case 0: // ProcessBasicInformation - PROCESS_BASIC_INFORMATION (48 bytes on x64)
		const needed = 48
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write64(buffer+0, 0)                 // ExitStatus (NTSTATUS)
			ctx.Mem.Write32(buffer+4, 0)                 // padding
			ctx.Mem.Write64(buffer+8, ctx.State.PEBAddr) // PebBaseAddress
			ctx.Mem.Write64(buffer+16, 0xF)              // AffinityMask
			ctx.Mem.Write32(buffer+24, 8)                // BasePriority (NORMAL)
			ctx.Mem.Write32(buffer+28, 0)                // padding
			ctx.Mem.Write64(buffer+32, 4)                // UniqueProcessId
			ctx.Mem.Write64(buffer+40, 0)                // InheritedFromUniqueProcessId
		}
	case 1: // ProcessQuotaLimits - QUOTA_LIMITS (48 bytes)
		const needed = 48
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			for i := uint64(0); i < needed; i++ {
				ctx.Mem.Write8(buffer+i, 0)
			}
			ctx.Mem.Write64(buffer+0, 0x80000)     // MinimumWorkingSetSize
			ctx.Mem.Write64(buffer+8, 0x100000)    // MaximumWorkingSetSize
			ctx.Mem.Write64(buffer+16, ^uint64(0)) // PagedPoolLimit = unlimited
			ctx.Mem.Write64(buffer+24, ^uint64(0)) // NonPagedPoolLimit
			ctx.Mem.Write64(buffer+32, ^uint64(0)) // MinimumWorkingSetSize
			ctx.Mem.Write64(buffer+40, ^uint64(0)) // PagefileLimit
		}
	case 2: // ProcessIoCounters - IO_COUNTERS (48 bytes)
		const needed = 48
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			for i := uint64(0); i < needed; i++ {
				ctx.Mem.Write8(buffer+i, 0)
			}
		}
	case 3: // ProcessVmCounters - VM_COUNTERS_EX (80 bytes)
		const needed = 80
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			for i := uint64(0); i < needed; i++ {
				ctx.Mem.Write8(buffer+i, 0)
			}
			ctx.Mem.Write64(buffer+0, 0x10000) // PeakVirtualSize
			ctx.Mem.Write64(buffer+8, 0x10000) // VirtualSize
			ctx.Mem.Write64(buffer+24, 0x1000) // PeakWorkingSetSize
			ctx.Mem.Write64(buffer+32, 0x1000) // WorkingSetSize
		}
	case 4: // ProcessTimes - KERNEL_USER_TIMES (32 bytes)
		const needed = 32
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			now := uint64(time.Now().UnixNano()/100 + 116444736000000000) // FILETIME
			ctx.Mem.Write64(buffer+0, now)                                // CreateTime
			ctx.Mem.Write64(buffer+8, 0)                                  // ExitTime
			ctx.Mem.Write64(buffer+16, 0)                                 // KernelTime (100ns units)
			ctx.Mem.Write64(buffer+24, 0)                                 // UserTime
		}
	case 5: // ProcessBasePriority
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 8) // NORMAL_PRIORITY_CLASS
		}
	case 7: // ProcessDebugPort - NULL = no debugger
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0)
		}
	case 9: // ProcessWow64Information - NULL = 64-bit process
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0) // not WOW64
		}
	case 11: // ProcessHandleCount
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, uint32(ctx.Handles.Count()))
		}
	case 12: // ProcessAffinityMask
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0xF) // 4 CPUs
		}
	case 17: // ProcessSessionInformation - PROCESS_SESSION_INFORMATION (4 bytes)
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0) // Session 0
		}
	case 18: // ProcessWx86Information (return 0 = no x86 emulation)
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0)
		}
	case 20: // ProcessDeviceMap
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0)
		}
	case 22: // ProcessPriorityClass - PROCESS_PRIORITY_CLASS (2 bytes)
		writeRetLen(2)
		if buffer != 0 {
			ctx.Mem.Write8(buffer+0, 0) // Foreground = false
			ctx.Mem.Write8(buffer+1, 2) // PriorityClass = NORMAL
		}
	case 27: // ProcessImageFileName - UNICODE_STRING + data
		imgName := ctx.State.ImagePath
		if imgName == "" {
			imgName = "program.exe"
		}
		imgPath := `\Device\HarddiskVolume1\` + imgName
		utf16 := encodeUTF16LE(imgPath)
		needed := uint32(16 + len(utf16) + 2)
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write16(buffer+0, uint16(len(utf16)))   // Length
			ctx.Mem.Write16(buffer+2, uint16(len(utf16)+2)) // MaximumLength
			ctx.Mem.Write64(buffer+8, buffer+16)            // Buffer pointer
			ctx.Mem.WriteBytes(buffer+16, utf16)
			ctx.Mem.Write16(buffer+16+uint64(len(utf16)), 0) // null terminator
		}
	case 29: // ProcessBreakOnTermination
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0) // not a critical process
		}
	case 30: // ProcessDebugObjectHandle - STATUS_PORT_NOT_SET when no debugger
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0)
		}
		return 0xC0000353 // STATUS_PORT_NOT_SET
	case 31: // ProcessDebugFlags
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 1) // PROCESS_NO_DEBUG_INHERIT
		}
	case 33: // ProcessDefaultHardErrorMode
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0)
		}
	case 34: // ProcessHandleTracing
		return StatusNotImplemented
	case 36: // ProcessImageFileName (Win32) - same as 27
		imgName := ctx.State.ImagePath
		if imgName == "" {
			imgName = "program.exe"
		}
		imgPath := `\Device\HarddiskVolume1\` + imgName
		utf16 := encodeUTF16LE(imgPath)
		needed := uint32(16 + len(utf16) + 2)
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write16(buffer+0, uint16(len(utf16)))
			ctx.Mem.Write16(buffer+2, uint16(len(utf16)+2))
			ctx.Mem.Write64(buffer+8, buffer+16)
			ctx.Mem.WriteBytes(buffer+16, utf16)
			ctx.Mem.Write16(buffer+16+uint64(len(utf16)), 0)
		}
	case 40: // ProcessCookie - random cookie for stack canary
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0x12345678)
		}
	case 43: // ProcessImageInformation - SECTION_IMAGE_INFORMATION (48 bytes)
		const needed = 48
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			imageBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10) // PEB.ImageBaseAddress
			ctx.Mem.Write64(buffer+0, imageBase)                     // TransferAddress
			ctx.Mem.Write32(buffer+8, 0)                             // ZeroBits
			ctx.Mem.Write64(buffer+16, 0x100000)                     // MaximumStackSize
			ctx.Mem.Write64(buffer+24, 0x1000)                       // CommittedStackSize
			ctx.Mem.Write32(buffer+32, 0)                            // SubSystemType (native=0)
			ctx.Mem.Write16(buffer+36, 6)                            // MinorSubsystemVersion
			ctx.Mem.Write16(buffer+38, 1)                            // MajorSubsystemVersion
			ctx.Mem.Write32(buffer+40, 0)                            // GpValue
			ctx.Mem.Write16(buffer+44, 0x100)                        // ImageCharacteristics
			ctx.Mem.Write16(buffer+46, 0x8664)                       // DllCharacteristics (AMD64)
		}
	case 60: // ProcessCommandLineInformation - UNICODE_STRING + command line
		cmdLine := ""
		if ctx.State != nil {
			paramsAddr, _ := ctx.Mem.Read64(ctx.State.PEBAddr + PebProcessParameters)
			if paramsAddr != 0 {
				cmdLine = readGuestUnicodeString(ctx.Mem, paramsAddr+ProcessParamsCommandLine)
			}
		}
		if cmdLine == "" && ctx.State != nil {
			cmdLine = ctx.State.ImagePath
		}
		if cmdLine == "" {
			cmdLine = "program.exe"
		}
		utf16 := encodeUTF16LE(cmdLine)
		needed := uint32(16 + len(utf16) + 2)
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write16(buffer+0, uint16(len(utf16)))
			ctx.Mem.Write16(buffer+2, uint16(len(utf16)+2))
			ctx.Mem.Write64(buffer+8, buffer+16)
			ctx.Mem.WriteBytes(buffer+16, utf16)
			ctx.Mem.Write16(buffer+16+uint64(len(utf16)), 0)
		}
	case 61: // ProcessProtectionInformation
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0) // no protection level
		}
	case 64: // ProcessMitigationPolicy
		writeRetLen(0)
	case 77: // ProcessConsoleHostProcess
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0) // no console host process
		}
	default:
		return StatusNotImplemented
	}

	return StatusSuccess
}

func handleNtQueryInformationThread(ctx *TrapContext) uint32 {
	// NtQueryInformationThread(ThreadHandle, ThreadInformationClass, ThreadInformation, ThreadInformationLength, ReturnLength)
	threadHandle := ctx.Handles.GetThread(Handle(ctx.Arg(0)))
	infoClass := uint32(ctx.Arg(1))
	buffer := ctx.Arg(2)
	bufLen := uint32(ctx.Arg(3))
	retLen := ctx.Arg(4)

	writeRetLen := func(n uint32) {
		if retLen != 0 {
			ctx.Mem.Write32(retLen, n)
		}
	}

	switch infoClass {
	case 0: // ThreadBasicInformation - THREAD_BASIC_INFORMATION (48 bytes)
		const needed = 48
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		tid := uint64(1)
		priority := uint32(8)
		if threadHandle != nil {
			tid = uint64(threadHandle.TID)
			priority = uint32(threadHandle.Priority)
		} else if ctx.State != nil && ctx.State.ThreadId != 0 {
			tid = uint64(ctx.State.ThreadId)
		}
		if buffer != 0 {
			ctx.Mem.Write64(buffer+0, 0) // ExitStatus
			if ctx.State != nil {
				ctx.Mem.Write64(buffer+8, uint64(ctx.State.TEBAddr)) // TebBaseAddress
				ctx.Mem.Write64(buffer+16, uint64(ctx.State.ProcessId))
			}
			ctx.Mem.Write64(buffer+24, tid)      // ClientId.UniqueThread
			ctx.Mem.Write64(buffer+32, 0xF)      // AffinityMask
			ctx.Mem.Write32(buffer+40, priority) // Priority
			ctx.Mem.Write32(buffer+44, priority) // BasePriority
		}
	case 1: // ThreadTimes - KERNEL_USER_TIMES (32 bytes)
		const needed = 32
		writeRetLen(needed)
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			now := uint64(time.Now().UnixNano()/100 + 116444736000000000)
			ctx.Mem.Write64(buffer+0, now) // CreateTime
			ctx.Mem.Write64(buffer+8, 0)   // ExitTime
			ctx.Mem.Write64(buffer+16, 0)  // KernelTime
			ctx.Mem.Write64(buffer+24, 0)  // UserTime
		}
	case 2: // ThreadPriority
		writeRetLen(4)
		if buffer != 0 {
			priority := uint32(8)
			if threadHandle != nil {
				priority = uint32(threadHandle.Priority)
			}
			ctx.Mem.Write32(buffer, priority)
		}
	case 3: // ThreadBasePriority
		writeRetLen(4)
		if buffer != 0 {
			basePriority := uint32(8)
			if threadHandle != nil {
				basePriority = uint32(threadHandle.Priority)
			}
			ctx.Mem.Write32(buffer, basePriority)
		}
	case 4: // ThreadAffinityMask
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0xF)
		}
	case 9: // ThreadQuerySetWin32StartAddress
		writeRetLen(8)
		if buffer != 0 {
			ctx.Mem.Write64(buffer, 0) // not tracked
		}
	case 14: // ThreadHideFromDebugger (query: returns BOOLEAN)
		writeRetLen(1)
		if buffer != 0 {
			hidden := uint8(0)
			if threadHandle != nil && threadHandle.HideFromDebugger {
				hidden = 1
			}
			ctx.Mem.Write8(buffer, hidden)
		}
	case 16: // ThreadTebInformation
		writeRetLen(8)
		if buffer != 0 {
			teb := uint64(0)
			if ctx.State != nil {
				teb = uint64(ctx.State.TEBAddr)
			}
			ctx.Mem.Write64(buffer, teb)
		}
	case 19: // ThreadIoPriority
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 2) // NORMAL
		}
	case 27: // ThreadActualBasePriority
		writeRetLen(4)
		if buffer != 0 {
			priority := uint32(8)
			if threadHandle != nil {
				priority = uint32(threadHandle.Priority)
			}
			ctx.Mem.Write32(buffer, priority)
		}
	case 17: // ThreadIsTerminated
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0) // running
		}
	case 34: // ThreadSuspendCount
		writeRetLen(4)
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0)
		}
	default:
		return StatusNotImplemented
	}

	return StatusSuccess
}

func handleNtQuerySystemInformation(ctx *TrapContext) uint32 {
	infoClass := uint32(ctx.Arg(0))
	buffer := ctx.Arg(1)
	length := uint32(ctx.Arg(2))
	retLen := ctx.Arg(3)
	writeRetLen := func(n uint32) {
		if retLen != 0 {
			ctx.Mem.Write32(retLen, n)
		}
	}

	switch infoClass {
	case 0: // SystemBasicInformation
		const needed = 56
		writeRetLen(needed)
		if buffer == 0 || length < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			ctx.Mem.Write32(buffer+0, 0)                       // Reserved
			ctx.Mem.Write32(buffer+4, 100)                     // TimerResolution
			ctx.Mem.Write32(buffer+8, uint32(mmu.PageSize))    // PageSize
			ctx.Mem.Write32(buffer+12, 262144)                 // NumberOfPhysicalPages
			ctx.Mem.Write32(buffer+16, 256)                    // LowestPhysicalPageNumber
			ctx.Mem.Write32(buffer+20, 262144)                 // HighestPhysicalPageNumber
			ctx.Mem.Write32(buffer+24, uint32(mmu.PageSize))   // AllocationGranularity
			ctx.Mem.Write64(buffer+28, 0x10000)                // MinimumUserModeAddress
			ctx.Mem.Write64(buffer+36, 0x7FFFFFFEFFFF)         // MaximumUserModeAddress
			ctx.Mem.Write64(buffer+44, 0xF)                    // ActiveProcessorsAffinityMask
			ctx.Mem.Write8(buffer+52, uint8(runtime.NumCPU())) // NumberOfProcessors
		}
	case 1: // SystemProcessorInformation
		if buffer != 0 {
			ctx.Mem.Write16(buffer+0, 9) // ProcessorArchitecture = AMD64
			ctx.Mem.Write16(buffer+2, 0) // ProcessorLevel
			ctx.Mem.Write16(buffer+4, 0) // ProcessorRevision
		}

	case 2: // SystemPerformanceInformation (256 bytes SYSTEM_PERFORMANCE_INFORMATION)
		if buffer != 0 {
			total := uint64(1 * 1024 * 1024 * 1024) // 1GB total virtual
			now := uint64(time.Now().UnixNano() / 100)
			ctx.Mem.Write64(buffer+0, now)                           // IdleProcessTime
			ctx.Mem.Write64(buffer+8, 0)                             // IoReadTransferCount
			ctx.Mem.Write64(buffer+16, 0)                            // IoWriteTransferCount
			ctx.Mem.Write64(buffer+24, 0)                            // IoOtherTransferCount
			ctx.Mem.Write32(buffer+32, 0)                            // IoReadOperationCount
			ctx.Mem.Write32(buffer+36, 0)                            // IoWriteOperationCount
			ctx.Mem.Write32(buffer+40, 0)                            // IoOtherOperationCount
			ctx.Mem.Write32(buffer+44, uint32(total/mmu.PageSize))   // AvailablePages
			ctx.Mem.Write32(buffer+48, uint32(total/mmu.PageSize))   // CommittedPages
			ctx.Mem.Write32(buffer+52, uint32(total*2/mmu.PageSize)) // CommitLimit
			ctx.Mem.Write32(buffer+56, 0)                            // PeakCommitment
			ctx.Mem.Write32(buffer+60, 1024*1024)                    // PageFaultCount
			ctx.Mem.Write32(buffer+64, 0)                            // CopyOnWriteCount
			ctx.Mem.Write32(buffer+68, 0)                            // TransitionCount
			ctx.Mem.Write32(buffer+72, 0)                            // CacheTransitionCount
			ctx.Mem.Write32(buffer+76, 0)                            // DemandZeroCount
			ctx.Mem.Write32(buffer+80, 0)                            // PageReadCount
			ctx.Mem.Write32(buffer+84, 0)                            // PageReadIoCount
			ctx.Mem.Write32(buffer+88, 0)                            // CacheReadCount
			ctx.Mem.Write32(buffer+92, 0)                            // CacheIoCount
			ctx.Mem.Write32(buffer+96, 0)                            // DirtyPagesWriteCount
			ctx.Mem.Write32(buffer+100, 0)                           // DirtyWriteIoCount
			ctx.Mem.Write32(buffer+104, 0)                           // MappedPagesWriteCount
			ctx.Mem.Write32(buffer+108, 0)                           // MappedWriteIoCount
			ctx.Mem.Write32(buffer+112, uint32(total/mmu.PageSize))  // PagedPoolPages
			ctx.Mem.Write32(buffer+116, 1024)                        // NonPagedPoolPages
			ctx.Mem.Write32(buffer+120, 0)                           // PagedPoolAllocs
			ctx.Mem.Write32(buffer+124, 0)                           // PagedPoolFrees
			ctx.Mem.Write32(buffer+128, 0)                           // NonPagedPoolAllocs
			ctx.Mem.Write32(buffer+132, 0)                           // NonPagedPoolFrees
			ctx.Mem.Write32(buffer+136, 4096)                        // FreeSystemPtes
			ctx.Mem.Write32(buffer+140, 1024)                        // ResidentSystemCodePage
			ctx.Mem.Write32(buffer+144, 0)                           // TotalSystemDriverPages
			ctx.Mem.Write32(buffer+148, 0)                           // TotalSystemCodePages
			ctx.Mem.Write32(buffer+152, 0)                           // NonPagedPoolLookasideHits
			ctx.Mem.Write32(buffer+156, 0)                           // PagedPoolLookasideHits
			ctx.Mem.Write32(buffer+160, 0)                           // Spare3Count
			ctx.Mem.Write32(buffer+164, 0)                           // ResidentSystemCachePage
			ctx.Mem.Write32(buffer+168, 0)                           // ResidentPagedPoolPage
			ctx.Mem.Write32(buffer+172, 0)                           // ResidentSystemDriverPage
			ctx.Mem.Write32(buffer+176, 0)                           // CcFastReadNoWait
			ctx.Mem.Write32(buffer+180, 0)                           // CcFastReadWait
			ctx.Mem.Write32(buffer+184, 0)                           // CcFastReadResourceMiss
			ctx.Mem.Write32(buffer+188, 0)                           // CcFastReadNotPossible
			ctx.Mem.Write32(buffer+192, 0)                           // CcFastMdlReadNoWait
			ctx.Mem.Write32(buffer+196, 0)                           // CcFastMdlReadWait
			ctx.Mem.Write32(buffer+200, 0)                           // CcFastMdlReadResourceMiss
			ctx.Mem.Write32(buffer+204, 0)                           // CcFastMdlReadNotPossible
			ctx.Mem.Write32(buffer+208, 0)                           // CcMapDataNoWait
			ctx.Mem.Write32(buffer+212, 0)                           // CcMapDataWait
			ctx.Mem.Write32(buffer+216, 0)                           // CcMapDataNoWaitMiss
			ctx.Mem.Write32(buffer+220, 0)                           // CcMapDataWaitMiss
			ctx.Mem.Write32(buffer+224, 0)                           // CcPinMappedDataCount
			ctx.Mem.Write32(buffer+228, 0)                           // CcPinReadNoWait
			ctx.Mem.Write32(buffer+232, 0)                           // CcPinReadWait
			ctx.Mem.Write32(buffer+236, 0)                           // CcPinReadNoWaitMiss
			ctx.Mem.Write32(buffer+240, 0)                           // CcPinReadWaitMiss
			ctx.Mem.Write32(buffer+244, 0)                           // CcCopyReadNoWait
			ctx.Mem.Write32(buffer+248, 0)                           // CcCopyReadWait
			ctx.Mem.Write32(buffer+252, 0)                           // CcCopyReadNoWaitMiss
		}

	case 3: // SystemTimeOfDayInformation (48 bytes)
		const needed = 48
		writeRetLen(needed)
		if buffer == 0 || length < needed {
			return StatusBufferTooSmall
		}
		if buffer != 0 {
			now := uint64(time.Now().UnixNano()/100 + 116444736000000000)
			ctx.Mem.Write64(buffer+0, 0)
			ctx.Mem.Write64(buffer+8, now)
			ctx.Mem.Write64(buffer+16, 0)
			ctx.Mem.Write32(buffer+24, 0)
			ctx.Mem.Write32(buffer+28, 0)
			ctx.Mem.Write64(buffer+32, 0)
			ctx.Mem.Write64(buffer+40, 0)
		}

	case 5: // SystemProcessInformation - minimal single-process entry
		imageName := "Raven"
		if ctx.State != nil && ctx.State.ImagePath != "" {
			imageName = ctx.State.ImagePath
			if slash := strings.LastIndexAny(imageName, `\/`); slash >= 0 {
				imageName = imageName[slash+1:]
			}
		}
		nameBytes := encodeUTF16LE(imageName)
		needed := uint32(0x100 + len(nameBytes) + 2)
		writeRetLen(needed)
		if buffer == 0 || length < needed {
			return StatusBufferTooSmall
		}
		ctx.Mem.Write32(buffer+0, 0)
		ctx.Mem.Write32(buffer+4, 1)
		ctx.Mem.Write64(buffer+8, 0)
		ctx.Mem.Write32(buffer+16, 0)
		ctx.Mem.Write32(buffer+20, 1)
		ctx.Mem.Write64(buffer+24, 0)
		ctx.Mem.Write64(buffer+32, 0)
		ctx.Mem.Write64(buffer+40, 0)
		ctx.Mem.Write64(buffer+48, 0)
		ctx.Mem.Write16(buffer+56, uint16(len(nameBytes)))
		ctx.Mem.Write16(buffer+58, uint16(len(nameBytes)+2))
		ctx.Mem.Write32(buffer+60, 0)
		ctx.Mem.Write64(buffer+64, buffer+0x100)
		ctx.Mem.Write32(buffer+72, 8)
		pid := uint64(4)
		if ctx.State != nil && ctx.State.ProcessId != 0 {
			pid = uint64(ctx.State.ProcessId)
		}
		ctx.Mem.Write64(buffer+80, pid)
		ctx.Mem.Write64(buffer+88, 0)
		ctx.Mem.Write32(buffer+96, uint32(ctx.Handles.Count()))
		ctx.Mem.Write32(buffer+100, 0)
		ctx.Mem.WriteBytes(buffer+0x100, nameBytes)
		ctx.Mem.Write16(buffer+0x100+uint64(len(nameBytes)), 0)

	case 7: // SystemProcessorSpeedInformation / SystemNumaProcessorMap
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0) // HighestNodeNumber = 0
			ctx.Mem.Write32(buffer+4, 0)
		}

	case 16: // SystemHandleInformation
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0)   // NumberOfHandles
			ctx.Mem.Write32(buffer+4, 0) // Reserved
		}

	case 18: // SystemPagefileInformation
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 0)          // NextEntryOffset
			ctx.Mem.Write32(buffer+4, 512*1024) // TotalSize (in pages)
			ctx.Mem.Write32(buffer+8, 0)        // TotalInUse
			ctx.Mem.Write32(buffer+12, 0)       // PeakUsage
			// PageFileName is empty UNICODE_STRING at +16
		}

	case 21: // SystemFileCacheInformation
		if buffer != 0 {
			total := uint64(256 * 1024 * 1024)             // 256MB cache
			ctx.Mem.Write64(buffer, total/mmu.PageSize)    // CurrentSize
			ctx.Mem.Write64(buffer+8, total/mmu.PageSize)  // PeakSize
			ctx.Mem.Write32(buffer+16, 0)                  // PageFaultCount
			ctx.Mem.Write64(buffer+24, total/mmu.PageSize) // MinimumWorkingSet
			ctx.Mem.Write64(buffer+32, total/mmu.PageSize) // MaximumWorkingSet
			ctx.Mem.Write64(buffer+40, total/mmu.PageSize) // CurrentSizeIncludingTransitionInPages
			ctx.Mem.Write64(buffer+48, total/mmu.PageSize) // PeakSizeIncludingTransitionInPages
			ctx.Mem.Write64(buffer+56, 0)                  // TransitionRePurposeCount
			ctx.Mem.Write32(buffer+64, 0)                  // Flags
		}

	case 35: // SystemKernelDebuggerInformation
		if buffer != 0 {
			ctx.Mem.Write8(buffer, 0)   // KernelDebuggerEnabled = FALSE
			ctx.Mem.Write8(buffer+1, 1) // KernelDebuggerNotPresent = TRUE
		}

	case 37: // SystemRegistryQuotaInformation
		if buffer != 0 {
			ctx.Mem.Write32(buffer, 128*1024*1024) // RegistryQuotaAllowed (128MB)
			ctx.Mem.Write32(buffer+4, 0)           // RegistryQuotaUsed
			ctx.Mem.Write64(buffer+8, 0)           // PagedPoolSize
		}

	case 45: // SystemLookasideInformation
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
	allocationType := uint32(ctx.Arg(4))
	protect := uint32(ctx.Arg(5))

	baseAddr, _ := ctx.Mem.Read64(basePtr)
	size, _ := ctx.Mem.Read64(sizePtr)

	if size == 0 {
		return StatusInvalidParameter
	}
	if allocationType&(memCommit|memReserve) == 0 {
		return StatusInvalidParameter
	}

	size = (size + mmu.PageSize - 1) & mmu.PageMask
	perms := NtMemProtectToMMU(protect)
	if perms == 0 {
		perms = mmu.PermRead | mmu.PermWrite
	}
	addr := ctx.Mem.Mmap(baseAddr, size, perms)
	if addr < 0x1000 {
		ravelog.Logf("[WARN] NtAllocateVirtualMemory failed addr=0x%x size=0x%x baseAddr=0x%x\n", addr, size, baseAddr)
		return StatusNoMemory
	}

	writeGuestPtr(ctx.Mem, basePtr, addr)
	writeGuestPtr(ctx.Mem, sizePtr, size)

	return StatusSuccess
}

func handleNtFreeVirtualMemory(ctx *TrapContext) uint32 {
	basePtr := ctx.Arg(1)
	sizePtr := ctx.Arg(2)
	freeType := uint32(ctx.Arg(3))

	baseAddr, _ := ctx.Mem.Read64(basePtr)
	size, _ := ctx.Mem.Read64(sizePtr)
	if baseAddr == 0 {
		return StatusInvalidParameter
	}
	if freeType&memRelease != 0 {
		_, regionSize, mapped, _ := ctx.Mem.QueryRegion(baseAddr)
		if mapped && regionSize > 0 {
			size = regionSize
		}
	} else if freeType&memDecommit != 0 {
		if size == 0 {
			_, regionSize, mapped, _ := ctx.Mem.QueryRegion(baseAddr)
			if mapped && regionSize > 0 {
				size = regionSize
			}
		}
	} else {
		return StatusInvalidParameter
	}
	if size == 0 {
		return StatusInvalidParameter
	}
	ctx.Mem.Munmap(baseAddr, size)
	writeGuestPtr(ctx.Mem, sizePtr, size)
	return StatusSuccess
}

func handleNtProtectVirtualMemory(ctx *TrapContext) uint32 {
	basePtr := ctx.Arg(1)
	sizePtr := ctx.Arg(2)
	newProtect := uint32(ctx.Arg(3))
	oldProtectPtr := ctx.Arg(4)

	baseAddr, _ := ctx.Mem.Read64(basePtr)
	size, _ := ctx.Mem.Read64(sizePtr)
	_, _, mapped, oldPerms := ctx.Mem.QueryRegion(baseAddr)
	if !mapped {
		return StatusInvalidParameter
	}
	perms := NtMemProtectToMMU(newProtect)
	if perms == 0 && newProtect != 0x01 {
		return StatusInvalidParameter
	}
	ctx.Mem.Mprotect(baseAddr, size, perms)
	if oldProtectPtr != 0 {
		ctx.Mem.Write32(oldProtectPtr, MMUPermsToNtProtect(oldPerms))
	}

	return StatusSuccess
}

func handleNtQueryVirtualMemory(ctx *TrapContext) uint32 {
	addr := ctx.Arg(1)
	infoClass := ctx.Arg(2)
	buffer := ctx.Arg(3)
	bufLen := ctx.Arg(4)
	retLen := ctx.Arg(5)
	if buffer == 0 {
		return StatusSuccess
	}

	switch infoClass {
	case 2: // MemorySectionName (UNICODE_STRING with image path for mapped files)
		// Find the loaded module containing this address so apps can ask for the
		// mapped file name of code/data pages.
		imagePath := ""
		if ctx.State != nil {
			ldrAddr, _ := ctx.Mem.Read64(ctx.State.PEBAddr + PebLdr)
			if ldrAddr != 0 {
				listHead := ldrAddr + LdrInLoadOrderModuleList
				flink, _ := ctx.Mem.Read64(listHead)
				for flink != 0 && flink != listHead {
					entry := flink
					base, _ := ctx.Mem.Read64(entry + LdrEntryDllBase)
					size, _ := ctx.Mem.Read32(entry + LdrEntrySizeOfImage)
					if base != 0 && addr >= base && addr < base+uint64(size) {
						imagePath = readGuestUnicodeString(ctx.Mem, entry+LdrEntryFullDllName)
						break
					}
					flink, _ = ctx.Mem.Read64(flink)
				}
			}
			if imagePath == "" {
				pebBase, _ := ctx.Mem.Read64(ctx.State.PEBAddr + 0x10)
				if pebBase != 0 && addr >= pebBase {
					imagePath = ctx.State.ImagePath
				}
			}
		}
		if imagePath == "" {
			imagePath = `\Device\HarddiskVolume1\Windows\System32\unknown.dll`
		}
		// Convert Win32 path to an NT device path when necessary.
		if strings.HasPrefix(imagePath, `C:\`) {
			imagePath = `\Device\HarddiskVolume1\` + imagePath[3:]
		} else if strings.HasPrefix(imagePath, `/`) {
			imagePath = `\Device\HarddiskVolume1` + imagePath
		}
		// Write UNICODE_STRING followed by the path data
		// UNICODE_STRING: Length(2) + MaxLength(2) + pad(4) + Buffer(8) = 16 bytes
		wsBytes := encodeUTF16LE(imagePath)
		needed := uint64(16 + len(wsBytes) + 2)
		if retLen != 0 {
			writeGuestPtr(ctx.Mem, retLen, needed)
		}
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		strData := buffer + 16
		ctx.Mem.Write16(buffer, uint16(len(wsBytes)))     // Length
		ctx.Mem.Write16(buffer+2, uint16(len(wsBytes)+2)) // MaxLength
		ctx.Mem.Write32(buffer+4, 0)                      // padding
		ctx.Mem.Write64(buffer+8, strData)                // Buffer
		ctx.Mem.WriteBytes(strData, wsBytes)
		ctx.Mem.Write16(strData+uint64(len(wsBytes)), 0)
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
		state = 0x1000 // MEM_COMMIT
		typ = 0x20000  // MEM_PRIVATE
	} else {
		state = 0x10000 // MEM_FREE
		typ = 0
		protect = 0x01 // PAGE_NOACCESS
	}

	if ctx.Mem.Mode32 {
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 28)
		}
		if bufLen < 28 {
			return StatusBufferTooSmall
		}
		ctx.Mem.Write32(buffer+0, uint32(base))
		ctx.Mem.Write32(buffer+4, uint32(base))
		ctx.Mem.Write32(buffer+8, protect)
		ctx.Mem.Write32(buffer+12, uint32(size))
		ctx.Mem.Write32(buffer+16, state)
		ctx.Mem.Write32(buffer+20, protect)
		ctx.Mem.Write32(buffer+24, typ)
		return StatusSuccess
	}
	if retLen != 0 {
		ctx.Mem.Write64(retLen, 48)
	}
	if bufLen < 48 {
		return StatusBufferTooSmall
	}
	ctx.Mem.Write64(buffer+0, base)
	ctx.Mem.Write64(buffer+8, base)
	ctx.Mem.Write32(buffer+16, protect)
	ctx.Mem.Write32(buffer+20, 0)
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

	evt := NewEvent(!autoReset, false)

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

	evt.Reset()

	return StatusSuccess
}

func handleNtClearEvent(ctx *TrapContext) uint32 {
	return handleNtResetEvent(ctx)
}

func handleNtPulseEvent(ctx *TrapContext) uint32 {
	// NtPulseEvent(EventHandle, PreviousState*) - signal then immediately reset
	handle := Handle(ctx.Arg(0))
	prevPtr := ctx.Arg(1)
	evt := ctx.Handles.GetEvent(handle)
	if evt == nil {
		return StatusInvalidHandle
	}
	prev := evt.PeekSignaled()
	if prevPtr != 0 {
		if prev {
			ctx.Mem.Write32(prevPtr, 1)
		} else {
			ctx.Mem.Write32(prevPtr, 0)
		}
	}
	evt.Signal()
	// Auto-reset: clear immediately after waking (best effort)
	evt.Reset()
	return StatusSuccess
}

func handleNtQueryEvent(ctx *TrapContext) uint32 {
	// NtQueryEvent(EventHandle, EventInformationClass, EventInfo, Length, ReturnLength)
	handle := Handle(ctx.Arg(0))
	infoClass := ctx.Arg(1)
	buffer := ctx.Arg(2)
	bufLen := ctx.Arg(3)
	retLen := ctx.Arg(4)
	_ = infoClass // EventBasicInformation = 0
	const needed = 8
	if retLen != 0 {
		ctx.Mem.Write32(retLen, needed)
	}
	if bufLen < needed {
		return 0xC0000023
	}
	evt := ctx.Handles.GetEvent(handle)
	signaled := false
	eventType := uint32(0) // NotificationEvent
	if evt != nil {
		signaled = evt.PeekSignaled()
		if evt.IsManualReset() {
			eventType = 0 // NotificationEvent
		} else {
			eventType = 1 // SynchronizationEvent
		}
	}
	if buffer != 0 {
		ctx.Mem.Write32(buffer, eventType)
		if signaled {
			ctx.Mem.Write32(buffer+4, 1)
		} else {
			ctx.Mem.Write32(buffer+4, 0)
		}
	}
	return StatusSuccess
}

func handleNtQueryMutant(ctx *TrapContext) uint32 {
	// NtQueryMutant(MutantHandle, MutantInformationClass, MutantInfo, Length, ReturnLength)
	buffer := ctx.Arg(2)
	bufLen := ctx.Arg(3)
	retLen := ctx.Arg(4)
	const needed = 12
	if retLen != 0 {
		ctx.Mem.Write32(retLen, needed)
	}
	if bufLen < needed {
		return 0xC0000023
	}
	if buffer != 0 {
		ctx.Mem.Write32(buffer, 0)   // CurrentCount
		ctx.Mem.Write32(buffer+4, 0) // OwnedByCaller
		ctx.Mem.Write32(buffer+8, 0) // AbandonedState
	}
	return StatusSuccess
}

func handleNtQuerySemaphore(ctx *TrapContext) uint32 {
	// NtQuerySemaphore(SemHandle, SemInfoClass, SemInfo, Length, ReturnLength)
	handle := Handle(ctx.Arg(0))
	buffer := ctx.Arg(2)
	bufLen := ctx.Arg(3)
	retLen := ctx.Arg(4)
	const needed = 8
	if retLen != 0 {
		ctx.Mem.Write32(retLen, needed)
	}
	if bufLen < needed {
		return 0xC0000023
	}
	count, maxCount := int32(0), int32(1)
	sem := ctx.Handles.GetSemaphore(handle)
	if sem != nil {
		count = sem.Count()
		maxCount = sem.MaxCount()
	}
	if buffer != 0 {
		ctx.Mem.Write32(buffer, uint32(count))
		ctx.Mem.Write32(buffer+4, uint32(maxCount))
	}
	return StatusSuccess
}

func handleNtQueryTimerResolution(ctx *TrapContext) uint32 {
	// NtQueryTimerResolution(MinimumResolution*, MaximumResolution*, ActualResolution*)
	minPtr := ctx.Arg(0)
	maxPtr := ctx.Arg(1)
	curPtr := ctx.Arg(2)
	if minPtr != 0 {
		ctx.Mem.Write32(minPtr, 156250)
	} // 15.625ms in 100ns units
	if maxPtr != 0 {
		ctx.Mem.Write32(maxPtr, 5000)
	} // 0.5ms
	if curPtr != 0 {
		ctx.Mem.Write32(curPtr, 156250)
	} // 15.625ms current
	return StatusSuccess
}

// ──────────────────────────────────────────────────────────
// NtCreateKeyedEvent / NtOpenKeyedEvent / NtWaitForKeyedEvent / NtReleaseKeyedEvent
// Reference: reactos/ntoskrnl/ex/keyedevt.c
// Used by ntdll SRW locks, condition variables, critical section fallback
// ──────────────────────────────────────────────────────────

func handleNtCreateKeyedEvent(ctx *TrapContext) uint32 {
	outHandle := ctx.Arg(0)
	// arg1=DesiredAccess, arg2=ObjectAttributes, arg3=Flags - all ignored for now
	name := ""
	ke := NewKeyedEvent(name)
	h := ctx.Handles.Alloc(ke)
	if outHandle != 0 {
		ctx.Mem.Write64(outHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenKeyedEvent(ctx *TrapContext) uint32 {
	outHandle := ctx.Arg(0)
	// For now always return the global fallback event handle
	h := ctx.Handles.Alloc(GlobalKeyedEvent)
	if outHandle != 0 {
		ctx.Mem.Write64(outHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtWaitForKeyedEvent(ctx *TrapContext) uint32 {
	// NtWaitForKeyedEvent(Handle, Key, Alertable, Timeout*)
	hVal := Handle(ctx.Arg(0))
	key := ctx.Arg(1) // guest address used as key
	timeoutP := ctx.Arg(3)

	var ke *KeyedEventHandle
	if hVal == 0 || hVal == Handle(0xFFFFFFFFFFFFFFFF) {
		ke = GlobalKeyedEvent
	} else {
		ke = ctx.Handles.GetKeyedEvent(hVal)
		if ke == nil {
			ke = GlobalKeyedEvent
		}
	}

	d := ntWaitDuration(ctx, timeoutP)
	status := ke.Wait(key, d)
	return status
}

func handleNtReleaseKeyedEvent(ctx *TrapContext) uint32 {
	// NtReleaseKeyedEvent(Handle, Key, Alertable, Timeout*)
	hVal := Handle(ctx.Arg(0))
	key := ctx.Arg(1)
	timeoutP := ctx.Arg(3)

	var ke *KeyedEventHandle
	if hVal == 0 || hVal == Handle(0xFFFFFFFFFFFFFFFF) {
		ke = GlobalKeyedEvent
	} else {
		ke = ctx.Handles.GetKeyedEvent(hVal)
		if ke == nil {
			ke = GlobalKeyedEvent
		}
	}

	d := ntWaitDuration(ctx, timeoutP)
	status := ke.Release(key, d)
	return status
}

// ──────────────────────────────────────────────────────────
// NtAllocateUuids - generates UUID components
// Reference: reactos/ntoskrnl/ex/uuid.c
// ──────────────────────────────────────────────────────────
func handleNtAllocateUuids(ctx *TrapContext) uint32 {
	// NtAllocateUuids(Time*, Range*, Sequence*, Seed*)
	timePtr := ctx.Arg(0)
	rangePtr := ctx.Arg(1)
	seqPtr := ctx.Arg(2)
	seedPtr := ctx.Arg(3)

	// Use current time as the time component
	now := uint64(time.Now().UnixNano()/100 + 116444736000000000) // FILETIME
	if timePtr != 0 {
		ctx.Mem.Write64(timePtr, now)
	}
	if rangePtr != 0 {
		ctx.Mem.Write32(rangePtr, 1)
	}

	var seq [2]byte
	unix.Getrandom(seq[:], 0)
	if seqPtr != 0 {
		ctx.Mem.Write16(seqPtr, uint16(seq[0])|(uint16(seq[1])<<8))
	}

	var seed [8]byte
	unix.Getrandom(seed[:], 0)
	if seedPtr != 0 {
		for i, b := range seed {
			ctx.Mem.Write8(seedPtr+uint64(i), b)
		}
	}
	return StatusSuccess
}

func handleNtWaitForSingleObject(ctx *TrapContext) uint32 {
	handle := Handle(ctx.Arg(0))
	_ = ctx.Arg(1) // Alertable
	timeoutPtr := ctx.Arg(2)

	timeout := ntWaitDuration(ctx, timeoutPtr)

	return ntWaitOne(ctx, handle, timeout)
}

// ntWaitDuration converts an optional NT timeout pointer to a Go duration.
// Negative NT time = relative (100-ns units). Nil pointer = INFINITE.
func ntWaitDuration(ctx *TrapContext, ptr uint64) time.Duration {
	if ptr == 0 {
		return -1 // INFINITE
	}
	t, _ := ctx.Mem.Read64(ptr)
	if t == 0 {
		return 0 // poll
	}
	if int64(t) < 0 {
		return time.Duration(-int64(t)) * 100 * time.Nanosecond
	}
	// Absolute FILETIME: compute delta from now
	nowFT := uint64(time.Now().UnixNano()/100 + 116444736000000000)
	if t <= nowFT {
		return 0
	}
	return time.Duration(t-nowFT) * 100 * time.Nanosecond
}

// ntWaitOne waits on a single handle; returns NTSTATUS.
func ntWaitOne(ctx *TrapContext, h Handle, timeout time.Duration) uint32 {
	obj := ctx.Handles.Get(h)
	switch v := obj.(type) {
	case *EventHandle:
		if v.WaitTimeout(timeout) {
			return StatusWait0
		}
		return StatusTimeout
	case *MutantHandle:
		res := v.WaitTimeout(1, timeout) // TID=1 (simplified)
		if res == 0 {
			return StatusWait0
		}
		if res == 0x80 {
			return 0x00000080 // STATUS_ABANDONED_WAIT_0
		}
		return StatusTimeout
	case *SemaphoreHandle:
		res := v.WaitTimeout(timeout)
		if res == 0 {
			return StatusWait0
		}
		return StatusTimeout
	case *WaitableTimerHandle:
		res := v.WaitTimeout(timeout)
		if res == 0 {
			return StatusWait0
		}
		return StatusTimeout
	case *ThreadHandle:
		if v.Done == nil {
			return StatusWait0
		}
		if timeout < 0 {
			<-v.Done
			return StatusWait0
		}
		select {
		case <-v.Done:
			return StatusWait0
		case <-time.After(timeout):
			return StatusTimeout
		}
	case nil:
		return StatusInvalidHandle
	case *GenericHandle:
		switch strings.ToLower(v.Kind) {
		case "process", "thread":
			return StatusWait0
		default:
			return StatusWait0
		}
	default:
		// Unknown handle type - treat as signaled
		return StatusWait0
	}
}

func handleNtWaitForMultipleObjects(ctx *TrapContext) uint32 {
	// NtWaitForMultipleObjects(Count, Handles*, WaitType, Alertable, Timeout*)
	count := uint32(ctx.Arg(0))
	handlesPtr := ctx.Arg(1)
	waitAll := ctx.Arg(2) == 0 // 0=WaitAll, 1=WaitAny
	_ = ctx.Arg(3)             // Alertable
	timeoutPtr := ctx.Arg(4)

	if count == 0 || handlesPtr == 0 {
		return StatusWait0
	}
	if count > 64 {
		count = 64
	}

	timeout := ntWaitDuration(ctx, timeoutPtr)

	if !waitAll {
		// WaitAny: try each handle, return first signaled
		for i := uint32(0); i < count; i++ {
			hVal, _ := ctx.Mem.Read64(handlesPtr + uint64(i)*8)
			res := ntWaitOne(ctx, Handle(hVal), timeout)
			if res == StatusWait0 || res == 0x80 {
				return StatusWait0 + uint32(i)
			}
		}
		return StatusTimeout
	}

	// WaitAll: wait for each in sequence
	for i := uint32(0); i < count; i++ {
		hVal, _ := ctx.Mem.Read64(handlesPtr + uint64(i)*8)
		res := ntWaitOne(ctx, Handle(hVal), timeout)
		if res == StatusTimeout {
			return StatusTimeout
		}
	}
	return StatusWait0
}

func handleNtCreateMutant(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	_ = ctx.Arg(1) // DesiredAccess
	objAttr := ctx.Arg(2)
	initialOwner := ctx.Arg(3) != 0

	m := NewMutant(0)
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
		prev := mh.Count()
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
	return 0x40000024 // STATUS_NO_YIELD_PERFORMED
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
		ctx.Mem.Write64(csAddr+0, dbgInfo)    // DebugInfo pointer
		ctx.Mem.Write32(csAddr+8, 0xFFFFFFFF) // LockCount = -1 (unlocked)
		ctx.Mem.Write32(csAddr+12, 0)         // RecursionCount
		ctx.Mem.Write64(csAddr+16, 0)         // OwningThread
		ctx.Mem.Write64(csAddr+24, 0)         // LockSemaphore
		ctx.Mem.Write64(csAddr+32, 0)         // SpinCount
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

func handleRtlAcquireSRWExcl(ctx *TrapContext) uint32   { return StatusSuccess }
func handleRtlReleaseSRWExcl(ctx *TrapContext) uint32   { return StatusSuccess }
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
	_ = ctx.Arg(0) // HeapHandle
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

	ctx.Mem.Write16(destAddr+0, length)   // Length (bytes, not including null)
	ctx.Mem.Write16(destAddr+2, length+2) // MaximumLength
	ctx.Mem.Write64(destAddr+8, srcAddr)  // Buffer
	return StatusSuccess
}

// ======================== MISC ========================

func handleRtlGetVersion(ctx *TrapContext) uint32 {
	buffer := ctx.Arg(0) // PRTL_OSVERSIONINFOW

	if buffer != 0 {
		// RTL_OSVERSIONINFOEXW layout (284 bytes):
		//   +0x00  DWORD dwOSVersionInfoSize
		//   +0x04  DWORD dwMajorVersion
		//   +0x08  DWORD dwMinorVersion
		//   +0x0C  DWORD dwBuildNumber
		//   +0x10  DWORD dwPlatformId
		//   +0x14  WCHAR szCSDVersion[128]  (256 bytes, offsets 20..275)
		//   +0x114 WORD  wServicePackMajor  (offset 276)
		//   +0x116 WORD  wServicePackMinor
		//   +0x118 WORD  wSuiteMask
		//   +0x11A BYTE  wProductType
		//   +0x11B BYTE  wReserved
		structSize, _ := ctx.Mem.Read32(buffer)
		ctx.Mem.Write32(buffer+4, 10)     // dwMajorVersion
		ctx.Mem.Write32(buffer+8, 0)      // dwMinorVersion
		ctx.Mem.Write32(buffer+12, 19041) // dwBuildNumber
		ctx.Mem.Write32(buffer+16, 2)     // dwPlatformId = VER_PLATFORM_WIN32_NT
		// szCSDVersion[128]: empty string (null-terminate first WCHAR)
		ctx.Mem.Write16(buffer+20, 0)
		if structSize >= 284 { // RTL_OSVERSIONINFOEXW
			ctx.Mem.Write16(buffer+276, 0)     // wServicePackMajor
			ctx.Mem.Write16(buffer+278, 0)     // wServicePackMinor
			ctx.Mem.Write16(buffer+280, 0x300) // wSuiteMask: VER_SUITE_SINGLEUSERTS|VER_SUITE_TERMINAL
			ctx.Mem.Write8(buffer+282, 1)      // wProductType = VER_NT_WORKSTATION
			ctx.Mem.Write8(buffer+283, 0)      // wReserved
		}
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
	if ctx.State != nil && ctx.State.TEBAddr != 0 {
		off := uint64(TebLastErrorValue)
		if ctx.State.Is32 {
			off = Teb32LastErrorValue
		}
		ctx.Mem.Write32(ctx.State.TEBAddr+off, errorCode)
	}
	return StatusSuccess
}

func handleRtlGetLastWin32Error(ctx *TrapContext) uint32 {
	if ctx.State != nil && ctx.State.TEBAddr != 0 {
		off := uint64(TebLastErrorValue)
		if ctx.State.Is32 {
			off = Teb32LastErrorValue
		}
		val, err := ctx.Mem.Read32(ctx.State.TEBAddr + off)
		if err == nil {
			ctx.CPU.SetSyscallReturn(uint64(val))
			return val
		}
	}
	return 0
}

func handleNtDuplicateObject(ctx *TrapContext) uint32 {
	_ = Handle(ctx.Arg(0)) // SourceProcessHandle
	_ = Handle(ctx.Arg(1)) // TargetProcessHandle  (not used for same-process)
	srcHandle := Handle(ctx.Arg(2))
	targetHandlePtr := ctx.Arg(3)
	_ = ctx.Arg(4) // DesiredAccess
	_ = ctx.Arg(5) // HandleAttributes
	options := uint32(ctx.Arg(6))

	obj := ctx.Handles.Get(srcHandle)
	if obj == nil {
		return StatusInvalidHandle
	}

	cloned, status := cloneHandleObject(ctx, obj)
	if status != StatusSuccess {
		return status
	}
	newHandle := ctx.Handles.Alloc(cloned)
	if targetHandlePtr != 0 {
		writeGuestPtr(ctx.Mem, targetHandlePtr, uint64(newHandle))
	}

	if options&dupCloseSource != 0 {
		closeHandleObject(ctx, srcHandle, obj)
		ctx.Handles.Close(srcHandle)
	}
	_ = options & dupSameAccess

	return StatusSuccess
}

func handleNtQueryObject(ctx *TrapContext) uint32 {
	h := Handle(ctx.Arg(0))
	infoClass := ctx.Arg(1)
	buffer := ctx.Arg(2)
	bufLen := ctx.Arg(3)
	retLen := ctx.Arg(4)

	obj := ctx.Handles.Get(h)
	typeName := "Unknown"
	name := ""
	if obj != nil {
		switch strings.ToLower(obj.HandleType()) {
		case "file":
			typeName = "File"
			if fh := ctx.Handles.GetFile(h); fh != nil {
				name = `\\??\\` + VFSToNtPath(fh.Path)
			}
		case "event":
			typeName = "Event"
		case "mutant":
			typeName = "Mutant"
		case "semaphore":
			typeName = "Semaphore"
		case "thread":
			typeName = "Thread"
		case "process":
			typeName = "Process"
		case "section":
			typeName = "Section"
		default:
			typeName = obj.HandleType()
		}
		if name == "" {
			if n, ok := ctx.Handles.NameOf(h); ok && n != "" {
				name = `\BaseNamedObjects\` + n
			}
		}
	}
	dataOff := uint64(16)
	if ctx.Mem.Mode32 {
		dataOff = 8
	}
	switch infoClass {
	case 0: // ObjectBasicInformation (40 bytes)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 40)
		}
		if buffer == 0 || bufLen < 40 {
			return 0xC0000023
		}
		ctx.Mem.Write32(buffer, 0)     // Attributes
		ctx.Mem.Write32(buffer+4, 0xF) // GrantedAccess
		ctx.Mem.Write32(buffer+8, 1)   // HandleCount
		ctx.Mem.Write32(buffer+12, 1)  // PointerCount
		ctx.Mem.Write32(buffer+16, 0)  // PagedPoolCharge
		ctx.Mem.Write32(buffer+20, 0)  // NonPagedPoolCharge
		ctx.Mem.Write32(buffer+24, 0)  // Reserved[0]
		ctx.Mem.Write32(buffer+28, 0)  // Reserved[1]
		ctx.Mem.Write32(buffer+32, 0)  // Reserved[2]
		ctx.Mem.Write64(buffer+36, 0)  // NameInformationLength + TypeInformationLength
		return StatusSuccess
	case 1: // ObjectNameInformation (UNICODE_STRING + name)
		wsBytes := encodeUTF16LE(name)
		needed := uint64(dataOff + uint64(len(wsBytes)) + 2)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, uint32(needed))
		}
		if buffer == 0 {
			return StatusSuccess
		}
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		strData := buffer + dataOff
		ctx.Mem.Write16(buffer, uint16(len(wsBytes)))
		ctx.Mem.Write16(buffer+2, uint16(len(wsBytes)+2))
		if ctx.Mem.Mode32 {
			ctx.Mem.Write32(buffer+4, uint32(strData))
		} else {
			ctx.Mem.Write32(buffer+4, 0)
			ctx.Mem.Write64(buffer+8, strData)
		}
		ctx.Mem.WriteBytes(strData, wsBytes)
		ctx.Mem.Write16(strData+uint64(len(wsBytes)), 0)
		return StatusSuccess
	case 2: // ObjectTypeInformation
		wsBytes := encodeUTF16LE(typeName)
		needed := uint64(72 + len(wsBytes) + 2)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, uint32(needed))
		}
		if buffer == 0 {
			return StatusSuccess
		}
		if bufLen < needed {
			return StatusBufferTooSmall
		}
		strData := buffer + dataOff
		ctx.Mem.Write16(buffer, uint16(len(wsBytes)))
		ctx.Mem.Write16(buffer+2, uint16(len(wsBytes)+2))
		if ctx.Mem.Mode32 {
			ctx.Mem.Write32(buffer+4, uint32(strData))
		} else {
			ctx.Mem.Write32(buffer+4, 0)
			ctx.Mem.Write64(buffer+8, strData)
		}
		ctx.Mem.WriteBytes(strData, wsBytes)
		ctx.Mem.Write16(strData+uint64(len(wsBytes)), 0)
		return StatusSuccess
	case 3: // ObjectTypesInformation
		// Return a tiny but non-empty type count to satisfy callers that check >0.
		needed := uint32(4)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, needed)
		}
		if buffer == 0 {
			return StatusSuccess
		}
		if bufLen < uint64(needed) {
			return StatusBufferTooSmall
		}
		ctx.Mem.Write32(buffer, 1)
		return StatusSuccess
	case 4: // ObjectHandleFlagInformation
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 2)
		}
		if buffer == 0 || bufLen < 2 {
			return StatusBufferTooSmall
		}
		flags := objectHandleFlags[h]
		if flags&1 != 0 {
			ctx.Mem.Write8(buffer+0, 1) // Inherit
		} else {
			ctx.Mem.Write8(buffer+0, 0)
		}
		if flags&2 != 0 {
			ctx.Mem.Write8(buffer+1, 1) // ProtectFromClose
		} else {
			ctx.Mem.Write8(buffer+1, 0)
		}
		return StatusSuccess
	}
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
	if mem.Mode32 {
		mem.Write32(addr+4, uint32(info))
		return
	}
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
	var bufPtr uint64
	if mem.Mode32 {
		ptr32, _ := mem.Read32(addr + UnicodeString32Buffer)
		bufPtr = uint64(ptr32)
	} else {
		bufPtr, _ = mem.Read64(addr + UnicodeStringBuffer)
	}
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
func handleRtlReleasePebLock(ctx *TrapContext) uint32 { return StatusSuccess }

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
	_ = ctx.Arg(1) // MappedAsImage
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
		h := ctx.Handles.Alloc(NewDefaultTokenHandle())
		ctx.Mem.Write64(tokenHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenThreadToken(ctx *TrapContext) uint32 {
	tokenHandle := ctx.Arg(2)
	if tokenHandle != 0 {
		h := ctx.Handles.Alloc(NewDefaultTokenHandle())
		ctx.Mem.Write64(tokenHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtQueryInformationToken(ctx *TrapContext) uint32 {
	token := ctx.Handles.GetToken(Handle(ctx.Arg(0)))
	if token == nil {
		token = NewDefaultTokenHandle()
	}
	infoClass := uint32(ctx.Arg(1))
	outBuf := ctx.Arg(2)
	outLen := uint32(ctx.Arg(3))
	retLen := ctx.Arg(4)

	switch infoClass {
	case 1: // TokenUser - write a minimal SID
		sid := token.UserSID
		if len(sid) == 0 {
			sid = NewDefaultTokenHandle().UserSID
		}
		needed := uint32(16 + len(sid))
		if retLen != 0 {
			ctx.Mem.Write32(retLen, needed)
		}
		if outLen < needed {
			return 0xC0000023 // STATUS_BUFFER_TOO_SMALL
		}
		if outBuf != 0 {
			// TOKEN_USER: SID_AND_ATTRIBUTES (pointer + attributes)
			sidAddr := outBuf + 16
			ctx.Mem.Write64(outBuf, sidAddr) // SID pointer
			ctx.Mem.Write32(outBuf+8, 0)     // Attributes
			ctx.Mem.WriteBytes(sidAddr, sid)
		}
		return StatusSuccess
	case 25: // TokenElevation
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 4)
		}
		if outLen >= 4 && outBuf != 0 {
			if token.Elevated {
				ctx.Mem.Write32(outBuf, 1)
			} else {
				ctx.Mem.Write32(outBuf, 0)
			}
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
		ctx.Mem.Write32(luid, uint32(id)) // LowPart
		ctx.Mem.Write32(luid+4, 0)        // HighPart
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

func handleRtlGetUserInfoHeap(ctx *TrapContext) uint32  { return StatusSuccess }
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

func handleRtlCaptureContext(ctx *TrapContext) uint32 {
	pCtx := ctx.Arg(0)
	if pCtx == 0 {
		return StatusSuccess
	}
	_ = saveCPUContextToGuest(ctx.CPU, ctx.Mem, pCtx)
	return StatusSuccess
}

func restoreContextFromGuest(ctx *TrapContext, pCtx uint64) bool {
	if pCtx == 0 {
		return false
	}
	return restoreCPUContextFromGuest(ctx.CPU, ctx.Mem, pCtx) == nil
}

func handleRtlUnwind(ctx *TrapContext) uint32 {
	pCtx := ctx.Arg(1)
	restoreContextFromGuest(ctx, pCtx)
	return StatusSuccess
}

func handleRtlUnwindEx(ctx *TrapContext) uint32 {
	pCtx := ctx.Arg(1)
	restoreContextFromGuest(ctx, pCtx)
	return StatusSuccess
}
func handleRtlLookupFunctionEntry(ctx *TrapContext) uint32 {
	trampoline := AllocTrampoline(ctx.Mem)
	guestCall := func(addr uint64, args []uint64) (uint64, error) {
		return CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, addr, args, ctx.Trace)
	}
	_, imageBase, entryAddr := LookupFunctionEntry(ctx.Mem, ctx.Arg(0), guestCall)
	imageBasePtr := ctx.Arg(1)
	if imageBasePtr != 0 {
		ctx.Mem.Write64(imageBasePtr, imageBase)
	}
	ctx.SetReturn(entryAddr)
	return StatusSuccess
}
func handleRtlRestoreContext(ctx *TrapContext) uint32 {
	restoreContextFromGuest(ctx, ctx.Arg(0))
	return StatusSuccess
}

func handleRtlRaiseException(ctx *TrapContext) uint32 {
	// Best-effort dispatch to registered VEH handlers.
	// Full EXCEPTION_POINTERS marshalling is not implemented yet.
	if handlers := GlobalVEH.GetAll(); len(handlers) > 0 {
		if rw, ok := ctx.CPU.(RegisterWriter); ok {
			rw.WriteReg(regRCX, ctx.Arg(0)) // PEXCEPTION_RECORD
		}
		for _, h := range handlers {
			if h == nil || h.Addr == 0 {
				continue
			}
			rsp := ctx.CPU.GetSP()
			if rsp >= 8 {
				rsp -= 8
				ctx.Mem.Write64(rsp, ctx.CPU.GetPC())
				ctx.CPU.SetSP(rsp)
				ctx.CPU.SetPC(h.Addr)
				return StatusSuccess
			}
		}
	}
	return StatusSuccess
}
func handleRtlRaiseStatus(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlAddVectoredExceptionHandler(ctx *TrapContext) uint32 {
	first := ctx.Arg(0) != 0
	handler := ctx.Arg(1)
	h := GlobalVEH.Add(handler, first)
	ctx.SetReturn(h)
	return StatusSuccess
}

func handleRtlRemoveVectoredExceptionHandler(ctx *TrapContext) uint32 {
	GlobalVEH.Remove(ctx.Arg(0))
	ctx.SetReturn(1)
	return StatusSuccess
}

func handleRtlPcToFileHeader(ctx *TrapContext) uint32 {
	ctx.SetReturn(0)
	return StatusSuccess
}

func handleRtlGetEnabledExtendedFeatures(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // no extended features
	return StatusSuccess
}

func handleRtlSetUnhandledExceptionFilter(ctx *TrapContext) uint32 {
	if ctx.State != nil {
		prev := ctx.State.UnhandledExceptionFilter
		ctx.State.UnhandledExceptionFilter = ctx.Arg(0)
		ctx.SetReturn(prev)
	}
	return StatusSuccess
}

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
func handleNtSetInformationThread(ctx *TrapContext) uint32 {
	threadHandle := ctx.Handles.GetThread(Handle(ctx.Arg(0)))
	infoClass := uint32(ctx.Arg(1))

	switch infoClass {
	case 2, 3:
		if threadHandle != nil {
			threadHandle.Priority = int32(ctx.Arg(2))
		}
		return StatusSuccess
	case 0x11:
		if threadHandle != nil {
			threadHandle.HideFromDebugger = true
		}
		return StatusSuccess
	case 0, 1:
		return StatusSuccess
	default:
		return StatusInvalidParameter
	}
}

func handleNtOpenThread(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&GenericHandle{Kind: "Thread"})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtAlertThread(ctx *TrapContext) uint32       { return StatusSuccess }
func handleNtAlertResumeThread(ctx *TrapContext) uint32 { return StatusSuccess }
func handleNtTestAlert(ctx *TrapContext) uint32         { return StatusSuccess }

func handleNtCreateTimer(ctx *TrapContext) uint32 {
	// NtCreateTimer(TimerHandle*, DesiredAccess, ObjectAttributes*, TimerType)
	handlePtr := ctx.Arg(0)
	objAttr := ctx.Arg(2)
	timerType := ctx.Arg(3) // 0=NotificationTimer(manual), 1=SynchronizationTimer(auto)
	manualReset := timerType == 0

	timer := NewWaitableTimer(manualReset)

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
		h, isNew = ctx.Handles.AllocNamed(name, timer)
		if !isNew {
			if handlePtr != 0 {
				ctx.Mem.Write64(handlePtr, uint64(h))
			}
			return 0x40000000
		}
	} else {
		h = ctx.Handles.Alloc(timer)
	}
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtSetTimer(ctx *TrapContext) uint32 {
	// NtSetTimer(TimerHandle, DueTime*, ApcRoutine, ApcContext, Resume, Period, PreviousState*)
	h := Handle(ctx.Arg(0))
	dueTimePtr := ctx.Arg(1)
	period := int32(ctx.Arg(5)) // ms
	prevStatePtr := ctx.Arg(6)

	wt, ok := ctx.Handles.Get(h).(*WaitableTimerHandle)
	if !ok {
		return StatusInvalidHandle
	}

	if prevStatePtr != 0 {
		ctx.Mem.Write8(prevStatePtr, boolToByte(wt.IsSignaled()))
	}

	var dueNs int64
	if dueTimePtr != 0 {
		dueRaw, _ := ctx.Mem.Read64(dueTimePtr)
		dueInt := int64(dueRaw)
		if dueInt < 0 {
			// Relative time: negative 100-ns intervals
			dueNs = (-dueInt) * 100
		} else if dueInt > 0 {
			// Absolute FILETIME: convert to duration from now
			nowFT := uint64(time.Now().UnixNano()/100 + 116444736000000000)
			if uint64(dueInt) > nowFT {
				dueNs = int64(uint64(dueInt)-nowFT) * 100
			} else {
				dueNs = 0
			}
		}
	}

	due := time.Duration(dueNs)
	if due < 0 {
		due = 0
	}
	var periodDur time.Duration
	if period > 0 {
		periodDur = time.Duration(period) * time.Millisecond
	}
	wt.Set(due, periodDur)
	return StatusSuccess
}

func handleNtCancelTimer(ctx *TrapContext) uint32 {
	h := Handle(ctx.Arg(0))
	prevStatePtr := ctx.Arg(1)
	wt, ok := ctx.Handles.Get(h).(*WaitableTimerHandle)
	if !ok {
		return StatusInvalidHandle
	}
	if prevStatePtr != 0 {
		ctx.Mem.Write8(prevStatePtr, boolToByte(wt.IsSignaled()))
	}
	wt.Cancel()
	return StatusSuccess
}

func handleNtQueryTimer(ctx *TrapContext) uint32 {
	// NtQueryTimer(TimerHandle, TimerInformationClass, TimerInformation*, Length, ReturnLength*)
	h := Handle(ctx.Arg(0))
	buffer := ctx.Arg(2)
	retLen := ctx.Arg(4)

	wt, ok := ctx.Handles.Get(h).(*WaitableTimerHandle)
	const needed = 16 // TIMER_BASIC_INFORMATION: RemainingTime(8) + TimerState(4) + pad(4)
	if retLen != 0 {
		ctx.Mem.Write32(retLen, needed)
	}
	if buffer != 0 {
		ctx.Mem.Write64(buffer+0, 0) // RemainingTime (unknown without real tracking)
		if ok && wt.IsSignaled() {
			ctx.Mem.Write32(buffer+8, 1)
		} else {
			ctx.Mem.Write32(buffer+8, 0)
		}
	}
	return StatusSuccess
}

func boolToByte(b bool) uint8 {
	if b {
		return 1
	}
	return 0
}

var rtlCurrentDirectory = `C:\`
var rtlProcessEnv = map[string]string{
	"SYSTEMROOT": `C:\Windows`,
	"WINDIR":     `C:\Windows`,
	"TEMP":       `C:\Windows\Temp`,
	"TMP":        `C:\Windows\Temp`,
	"COMSPEC":    `C:\Windows\System32\cmd.exe`,
}
var rtlEnvBlocks = map[uint64]map[string]string{}

func normalizeDosPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return rtlCurrentDirectory
	}
	p = strings.ReplaceAll(p, "/", `\`)

	if strings.HasPrefix(p, `\??\`) {
		return p
	}
	if strings.HasPrefix(p, `\\?\`) {
		return `\??\` + strings.TrimPrefix(p, `\\?\`)
	}
	if strings.HasPrefix(p, `\\`) {
		return `\??\UNC\` + strings.TrimPrefix(p, `\\`)
	}
	if strings.HasPrefix(p, `\`) {
		drive := "C:"
		if len(rtlCurrentDirectory) >= 2 && rtlCurrentDirectory[1] == ':' {
			drive = rtlCurrentDirectory[:2]
		}
		p = drive + p
	} else if !(len(p) >= 2 && p[1] == ':') {
		base := rtlCurrentDirectory
		if base == "" {
			base = `C:\`
		}
		if !strings.HasSuffix(base, `\`) {
			base += `\`
		}
		p = base + p
	}
	return p
}

func dosPathToNtPath(path string) string {
	p := normalizeDosPath(path)
	if strings.HasPrefix(p, `\??\`) || strings.HasPrefix(p, `\Device\`) {
		return p
	}
	return `\??\` + p
}

func normalizeEnvKey(name string) string {
	return strings.ToUpper(strings.TrimSpace(name))
}

func cloneEnv(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func lookupEnvMap(envBlock uint64) map[string]string {
	if envBlock != 0 {
		if m, ok := rtlEnvBlocks[envBlock]; ok {
			return m
		}
	}
	return rtlProcessEnv
}

func lookupEnvValue(envBlock uint64, name string) (string, bool) {
	key := normalizeEnvKey(name)
	if key == "" {
		return "", false
	}
	if v, ok := lookupEnvMap(envBlock)[key]; ok {
		return v, true
	}
	if v, ok := rtlProcessEnv[key]; ok {
		return v, true
	}
	if v := os.Getenv(key); v != "" {
		return v, true
	}
	return "", false
}

func expandEnvVars(envBlock uint64, src string) string {
	var b strings.Builder
	for i := 0; i < len(src); {
		if src[i] != '%' {
			b.WriteByte(src[i])
			i++
			continue
		}
		j := strings.IndexByte(src[i+1:], '%')
		if j < 0 {
			b.WriteByte(src[i])
			i++
			continue
		}
		j = i + 1 + j
		name := src[i+1 : j]
		if val, ok := lookupEnvValue(envBlock, name); ok {
			b.WriteString(val)
		} else {
			b.WriteString(src[i : j+1])
		}
		i = j + 1
	}
	return b.String()
}

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
	_ = ctx.Arg(0)              // flags
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
	dosName := readGuestStringUTF16(ctx.Mem, ctx.Arg(0), 4096)
	ntNameUS := ctx.Arg(1)
	filePartPtr := ctx.Arg(2)
	if ntNameUS == 0 || dosName == "" {
		ctx.SetReturn(0)
		return StatusSuccess
	}

	ntPath := dosPathToNtPath(dosName)
	ntBytes := encodeUTF16LE(ntPath)
	buf := ctx.Mem.Mmap(0, uint64(len(ntBytes)+2), mmu.PermRead|mmu.PermWrite)
	ctx.Mem.WriteBytes(buf, ntBytes)
	ctx.Mem.Write16(buf+uint64(len(ntBytes)), 0)

	ctx.Mem.Write16(ntNameUS+UnicodeStringLength, uint16(len(ntBytes)))
	ctx.Mem.Write16(ntNameUS+UnicodeStringMaxLength, uint16(len(ntBytes)+2))
	ctx.Mem.Write64(ntNameUS+UnicodeStringBuffer, buf)

	if filePartPtr != 0 {
		lastSlash := strings.LastIndex(ntPath, `\`)
		if lastSlash >= 0 && lastSlash+1 < len(ntPath) {
			offsetBytes := uint64(len(encodeUTF16LE(ntPath[:lastSlash+1])))
			ctx.Mem.Write64(filePartPtr, buf+offsetBytes)
		} else {
			ctx.Mem.Write64(filePartPtr, 0)
		}
	}

	ctx.SetReturn(1)
	return StatusSuccess
}

func handleRtlDosPathNameToNtPathName_U_WithStatus(ctx *TrapContext) uint32 {
	_ = handleRtlDosPathNameToNtPathName_U(ctx)
	return StatusSuccess
}

func handleRtlGetCurrentDirectory_U(ctx *TrapContext) uint32 {
	bufLen := uint32(ctx.Arg(0))
	buf := ctx.Arg(1)
	cwd := rtlCurrentDirectory
	if cwd == "" {
		cwd = `C:\`
	}
	if buf != 0 && bufLen >= uint32(len(cwd)*2+2) {
		for i, ch := range []rune(cwd) {
			ctx.Mem.Write16(buf+uint64(i)*2, uint16(ch))
		}
		ctx.Mem.Write16(buf+uint64(len(cwd))*2, 0)
	}
	ctx.SetReturn(uint64(len(cwd) * 2))
	return StatusSuccess
}

func handleRtlSetCurrentDirectory_U(ctx *TrapContext) uint32 {
	pathUS := ctx.Arg(0)
	path := readGuestUnicodeString(ctx.Mem, pathUS)
	if path == "" {
		return StatusInvalidParameter
	}
	rtlCurrentDirectory = normalizeDosPath(path)
	if strings.HasPrefix(rtlCurrentDirectory, `\??\`) {
		rtlCurrentDirectory = strings.TrimPrefix(rtlCurrentDirectory, `\??\`)
	}
	return StatusSuccess
}

func handleRtlGetFullPathName_U(ctx *TrapContext) uint32 {
	fileName := readGuestStringUTF16(ctx.Mem, ctx.Arg(0), 4096)
	bufLen := uint32(ctx.Arg(1))
	buf := ctx.Arg(2)
	filePartPtr := ctx.Arg(3)
	if fileName == "" {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	fullPath := normalizeDosPath(fileName)
	if strings.HasPrefix(fullPath, `\??\`) {
		fullPath = strings.TrimPrefix(fullPath, `\??\`)
	}
	utf16Bytes := encodeUTF16LE(fullPath)
	required := uint32(len(utf16Bytes)) // bytes without null
	if buf == 0 || bufLen < required+2 {
		ctx.SetReturn(uint64(required + 2))
		if filePartPtr != 0 {
			ctx.Mem.Write64(filePartPtr, 0)
		}
		return StatusSuccess
	}
	ctx.Mem.WriteBytes(buf, utf16Bytes)
	ctx.Mem.Write16(buf+uint64(required), 0)
	if filePartPtr != 0 {
		lastSlash := strings.LastIndex(fullPath, `\`)
		if lastSlash >= 0 && lastSlash+1 < len(fullPath) {
			offset := uint64(len(encodeUTF16LE(fullPath[:lastSlash+1])))
			ctx.Mem.Write64(filePartPtr, buf+offset)
		} else {
			ctx.Mem.Write64(filePartPtr, 0)
		}
	}
	ctx.SetReturn(uint64(required))
	return StatusSuccess
}

func handleRtlDetermineDosPathNameType_U(ctx *TrapContext) uint32 {
	path := readGuestStringUTF16(ctx.Mem, ctx.Arg(0), 1024)
	switch {
	case strings.HasPrefix(path, `\??\`) || strings.HasPrefix(path, `\\?\`):
		ctx.SetReturn(5) // RtlPathTypeRootLocalDevice
	case strings.HasPrefix(path, `\\`):
		ctx.SetReturn(1) // RtlPathTypeUncAbsolute
	case len(path) >= 3 && path[1] == ':' && (path[2] == '\\' || path[2] == '/'):
		ctx.SetReturn(3) // RtlPathTypeDriveAbsolute
	case len(path) >= 2 && path[1] == ':':
		ctx.SetReturn(4) // RtlPathTypeDriveRelative
	case strings.HasPrefix(path, `\`):
		ctx.SetReturn(2) // RtlPathTypeRooted
	default:
		ctx.SetReturn(6) // RtlPathTypeRelative
	}
	return StatusSuccess
}

func handleRtlGetNtGlobalFlags(ctx *TrapContext) uint32 {
	// Return retail-like defaults: no debug heap/pageheap flags enabled.
	ctx.SetReturn(0)
	return StatusSuccess
}

func handleRtlGetNtProductType(ctx *TrapContext) uint32 {
	// BOOLEAN RtlGetNtProductType(NT_PRODUCT_TYPE* ProductType)
	out := ctx.Arg(0)
	if out == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	ctx.Mem.Write32(out, 1) // NtProductWinNt
	ctx.SetReturn(1)
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
	_ = ctx.Arg(0) // ProcessHandle
	processMachinePtr := ctx.Arg(1)
	nativeMachinePtr := ctx.Arg(2)
	const imageFileMachineAMD64 = 0x8664
	if processMachinePtr != 0 {
		ctx.Mem.Write16(processMachinePtr, imageFileMachineAMD64)
	}
	if nativeMachinePtr != 0 {
		ctx.Mem.Write16(nativeMachinePtr, imageFileMachineAMD64)
	}
	return StatusSuccess
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
	cloneCurrent := ctx.Arg(0) != 0
	envPtr := ctx.Arg(1)
	if envPtr != 0 {
		// Keep a guest pointer for API compatibility and track logical values in Go.
		envBuf := ctx.Mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write16(envBuf, 0)
		if cloneCurrent {
			rtlEnvBlocks[envBuf] = cloneEnv(rtlProcessEnv)
		} else {
			rtlEnvBlocks[envBuf] = map[string]string{
				"SYSTEMROOT": rtlProcessEnv["SYSTEMROOT"],
				"WINDIR":     rtlProcessEnv["WINDIR"],
				"TEMP":       rtlProcessEnv["TEMP"],
				"TMP":        rtlProcessEnv["TMP"],
				"COMSPEC":    rtlProcessEnv["COMSPEC"],
			}
		}
		ctx.Mem.Write64(envPtr, envBuf)
	}
	return StatusSuccess
}

func handleRtlDestroyEnvironment(ctx *TrapContext) uint32 {
	envBlock := ctx.Arg(0)
	if envBlock != 0 {
		delete(rtlEnvBlocks, envBlock)
	}
	return StatusSuccess
}

func handleRtlQueryEnvironmentVariable_U(ctx *TrapContext) uint32 {
	// RtlQueryEnvironmentVariable_U(Environment, Name, Value)
	envBlock := ctx.Arg(0)
	nameUS := ctx.Arg(1)
	valueUS := ctx.Arg(2)
	if nameUS == 0 || valueUS == 0 {
		return StatusInvalidParameter
	}
	name := readGuestUnicodeString(ctx.Mem, nameUS)
	val, ok := lookupEnvValue(envBlock, name)
	if !ok {
		return 0xC0000100 // STATUS_VARIABLE_NOT_FOUND
	}

	dstMax, _ := ctx.Mem.Read16(valueUS + UnicodeStringMaxLength)
	dstBuf, _ := ctx.Mem.Read64(valueUS + UnicodeStringBuffer)
	utf16Val := encodeUTF16LE(val)
	required := uint16(len(utf16Val))
	if dstBuf == 0 {
		return StatusInvalidParameter
	}
	if uint32(dstMax) < uint32(required)+2 {
		ctx.Mem.Write16(valueUS+UnicodeStringLength, required)
		return StatusBufferTooSmall
	}
	ctx.Mem.WriteBytes(dstBuf, utf16Val)
	ctx.Mem.Write16(dstBuf+uint64(required), 0)
	ctx.Mem.Write16(valueUS+UnicodeStringLength, required)
	return StatusSuccess
}

func handleRtlSetEnvironmentVariable(ctx *TrapContext) uint32 {
	// RtlSetEnvironmentVariable(PWSTR* Environment, Name, Value)
	envPtrPtr := ctx.Arg(0)
	nameUS := ctx.Arg(1)
	valueUS := ctx.Arg(2)
	if nameUS == 0 {
		return StatusInvalidParameter
	}
	name := normalizeEnvKey(readGuestUnicodeString(ctx.Mem, nameUS))
	if name == "" {
		return StatusInvalidParameter
	}

	var envBlock uint64
	var target map[string]string
	if envPtrPtr != 0 {
		envBlock, _ = ctx.Mem.Read64(envPtrPtr)
		if envBlock == 0 {
			envBlock = ctx.Mem.Mmap(0, 4, mmu.PermRead|mmu.PermWrite)
			ctx.Mem.Write16(envBlock, 0)
			ctx.Mem.Write64(envPtrPtr, envBlock)
			rtlEnvBlocks[envBlock] = cloneEnv(rtlProcessEnv)
		}
		target = lookupEnvMap(envBlock)
	} else {
		target = rtlProcessEnv
	}

	if valueUS == 0 {
		delete(target, name)
		return StatusSuccess
	}
	val := readGuestUnicodeString(ctx.Mem, valueUS)
	target[name] = val
	return StatusSuccess
}

func handleRtlExpandEnvironmentStrings_U(ctx *TrapContext) uint32 {
	// RtlExpandEnvironmentStrings_U(Environment, Source, Destination, ReturnedLength)
	envBlock := ctx.Arg(0) // optional environment block pointer
	srcUS := ctx.Arg(1)
	dstUS := ctx.Arg(2)
	returnLenPtr := ctx.Arg(3)
	if srcUS == 0 || dstUS == 0 {
		return StatusInvalidParameter
	}
	src := readGuestUnicodeString(ctx.Mem, srcUS)
	if src == "" {
		if returnLenPtr != 0 {
			ctx.Mem.Write32(returnLenPtr, 0)
		}
		ctx.Mem.Write16(dstUS+UnicodeStringLength, 0)
		return StatusSuccess
	}

	expanded := expandEnvVars(envBlock, src)

	dstMax, _ := ctx.Mem.Read16(dstUS + UnicodeStringMaxLength)
	dstBuf, _ := ctx.Mem.Read64(dstUS + UnicodeStringBuffer)
	outUTF16 := encodeUTF16LE(expanded)
	required := uint32(len(outUTF16))
	if returnLenPtr != 0 {
		ctx.Mem.Write32(returnLenPtr, required)
	}
	if dstBuf == 0 {
		return StatusInvalidParameter
	}
	if uint32(dstMax) < required+2 {
		ctx.Mem.Write16(dstUS+UnicodeStringLength, uint16(minUint32(required, uint32(dstMax))))
		return StatusBufferTooSmall
	}
	ctx.Mem.WriteBytes(dstBuf, outUTF16)
	ctx.Mem.Write16(dstBuf+uint64(len(outUTF16)), 0)
	ctx.Mem.Write16(dstUS+UnicodeStringLength, uint16(len(outUTF16)))
	return StatusSuccess
}

func handleRtlCreateProcessParametersEx(ctx *TrapContext) uint32 {
	paramsPtr := ctx.Arg(0)
	if paramsPtr != 0 {
		params := ctx.Mem.Mmap(0, 1024, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write32(params, 1024)  // MaximumLength
		ctx.Mem.Write32(params+4, 512) // Length
		ctx.Mem.Write64(paramsPtr, params)
	}
	return StatusSuccess
}

func handleRtlDestroyProcessParameters(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlRunOnceBeginInitialize(ctx *TrapContext) uint32 {
	return StatusSuccess // proceed with initialization
}

func handleRtlRunOnceComplete(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlRunOnceExecuteOnce(ctx *TrapContext) uint32 { return StatusSuccess }

func handleNtCreateIoCompletion(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	if handlePtr != 0 {
		h := ctx.Handles.Alloc(&IoCompletionPortHandle{})
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

func handleNtSetIoCompletion(ctx *TrapContext) uint32 {
	// NtSetIoCompletion(IoCompletionHandle, CompletionKey, CompletionContext, Status, Information)
	h := Handle(ctx.Arg(0))
	key := ctx.Arg(1)
	overlapped := ctx.Arg(2)
	status := uint32(ctx.Arg(3))
	info := uint32(ctx.Arg(4))
	iocp := ctx.Handles.GetIoCompletion(h)
	if iocp == nil {
		return StatusInvalidHandle
	}
	iocp.Post(key, overlapped, info, status)
	return StatusSuccess
}

func handleNtRemoveIoCompletion(ctx *TrapContext) uint32 {
	// NtRemoveIoCompletion(IoCompletionHandle, KeyContext, ApcContext, IoStatusBlock, Timeout)
	h := Handle(ctx.Arg(0))
	keyPtr := ctx.Arg(1)
	apcPtr := ctx.Arg(2)
	ioStatus := ctx.Arg(3)
	timeoutPtr := ctx.Arg(4)
	iocp := ctx.Handles.GetIoCompletion(h)
	if iocp == nil {
		return StatusInvalidHandle
	}

	timeout := time.Duration(-1)
	if timeoutPtr != 0 {
		t, _ := ctx.Mem.Read64(timeoutPtr)
		tv := int64(t)
		if tv == 0 {
			timeout = 0
		} else if tv < 0 {
			timeout = time.Duration(-tv) * 100 * time.Nanosecond
		} else {
			now := time.Now()
			const epochDiff = 11644473600
			ftNow := (now.Unix()+epochDiff)*10000000 + int64(now.Nanosecond()/100)
			rel := tv - ftNow
			if rel <= 0 {
				timeout = 0
			} else {
				timeout = time.Duration(rel) * 100 * time.Nanosecond
			}
		}
	}

	pkt, ok := iocp.Remove(timeout)
	if !ok {
		if ioStatus != 0 {
			writeIOStatus(ctx.Mem, ioStatus, StatusTimeout, 0)
		}
		return StatusTimeout
	}
	if keyPtr != 0 {
		ctx.Mem.Write64(keyPtr, pkt.CompletionKey)
	}
	if apcPtr != 0 {
		ctx.Mem.Write64(apcPtr, pkt.Overlapped)
	}
	if ioStatus != 0 {
		writeIOStatus(ctx.Mem, ioStatus, pkt.Status, uint64(pkt.BytesTransferred))
	}
	return StatusSuccess
}

func handleNtRemoveIoCompletionEx(ctx *TrapContext) uint32 {
	// NtRemoveIoCompletionEx(IoCompletionHandle, Entries, Count, NumRemoved, Timeout, Alertable)
	h := Handle(ctx.Arg(0))
	entries := ctx.Arg(1)
	count := uint32(ctx.Arg(2))
	removedPtr := ctx.Arg(3)
	timeoutPtr := ctx.Arg(4)
	_ = ctx.Arg(5) // Alertable
	iocp := ctx.Handles.GetIoCompletion(h)
	if iocp == nil {
		return StatusInvalidHandle
	}
	if entries == 0 || count == 0 {
		return StatusInvalidParameter
	}

	timeout := time.Duration(-1)
	if timeoutPtr != 0 {
		t, _ := ctx.Mem.Read64(timeoutPtr)
		tv := int64(t)
		if tv == 0 {
			timeout = 0
		} else if tv < 0 {
			timeout = time.Duration(-tv) * 100 * time.Nanosecond
		} else {
			now := time.Now()
			const epochDiff = 11644473600
			ftNow := (now.Unix()+epochDiff)*10000000 + int64(now.Nanosecond()/100)
			rel := tv - ftNow
			if rel <= 0 {
				timeout = 0
			} else {
				timeout = time.Duration(rel) * 100 * time.Nanosecond
			}
		}
	}

	removed := uint32(0)
	for removed < count {
		wait := time.Duration(0)
		if removed == 0 {
			wait = timeout
		}
		pkt, ok := iocp.Remove(wait)
		if !ok {
			break
		}
		// FILE_IO_COMPLETION_INFORMATION {KeyContext, ApcContext, IoStatusBlock}
		base := entries + uint64(removed)*24
		ctx.Mem.Write64(base+0, pkt.CompletionKey)
		ctx.Mem.Write64(base+8, pkt.Overlapped)
		ctx.Mem.Write32(base+16, pkt.Status)
		ctx.Mem.Write32(base+20, pkt.BytesTransferred)
		removed++
	}
	if removedPtr != 0 {
		ctx.Mem.Write32(removedPtr, removed)
	}
	if removed == 0 {
		return StatusTimeout
	}
	return StatusSuccess
}

func handleNtCancelIoFile(ctx *TrapContext) uint32 {
	ioStatus := ctx.Arg(1)
	writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 0)
	return StatusSuccess
}

func handleNtCancelIoFileEx(ctx *TrapContext) uint32 {
	ioStatus := ctx.Arg(2)
	writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 0)
	return StatusSuccess
}

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
	handlePtr := ctx.Arg(0)
	objAttr := ctx.Arg(2)
	if handlePtr == 0 || objAttr == 0 {
		return StatusInvalidParameter
	}
	_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
	if err != nil || oaName == "" {
		return StatusObjectNameNotFound
	}
	name := strings.ToLower(oaName)
	name = strings.ReplaceAll(name, "/", `\`)
	target := ""
	switch name {
	case `\??\nulssectionptr`, `\??\nlssectionptr`:
		target = `\Windows\System32\locale.nls`
	case `\??\conin$`:
		target = `\Device\ConDrv\Input`
	case `\??\conout$`:
		target = `\Device\ConDrv\Output`
	case `\??\pipe\`, `\device\namedpipe`:
		target = `\Device\NamedPipe`
	case `\systemroot`:
		target = `\Windows`
	default:
		return StatusObjectNameNotFound
	}
	h := ctx.Handles.Alloc(&SymbolicLinkHandle{Name: oaName, Target: target})
	ctx.Mem.Write64(handlePtr, uint64(h))
	return StatusSuccess
}

func handleNtQuerySymbolicLinkObject(ctx *TrapContext) uint32 {
	linkHandle := Handle(ctx.Arg(0))
	linkTarget := ctx.Arg(1) // PUNICODE_STRING
	retLen := ctx.Arg(2)     // PULONG
	if linkTarget == 0 {
		return StatusInvalidParameter
	}
	sl, ok := ctx.Handles.Get(linkHandle).(*SymbolicLinkHandle)
	if !ok || sl == nil {
		return StatusObjectTypeMismatch
	}
	ws := encodeUTF16LE(sl.Target)
	maxLen, _ := ctx.Mem.Read16(linkTarget + 2) // MaximumLength
	bufPtr, _ := ctx.Mem.Read64(linkTarget + 8) // Buffer
	if retLen != 0 {
		ctx.Mem.Write32(retLen, uint32(len(ws)))
	}
	if bufPtr == 0 {
		return StatusInvalidParameter
	}
	if uint32(maxLen) < uint32(len(ws)) {
		ctx.Mem.Write16(linkTarget+0, 0)
		return StatusBufferTooSmall
	}
	ctx.Mem.Write16(linkTarget+0, uint16(len(ws)))
	ctx.Mem.WriteBytes(bufPtr, ws)
	if uint32(maxLen) >= uint32(len(ws)+2) {
		ctx.Mem.Write16(bufPtr+uint64(len(ws)), 0)
	}
	return StatusSuccess
}

func handleNtSetSecurityObject(ctx *TrapContext) uint32 { return StatusSuccess }
func handleNtQuerySecurityObject(ctx *TrapContext) uint32 {
	_ = Handle(ctx.Arg(0)) // handle
	_ = ctx.Arg(1)         // security info mask
	secDesc := ctx.Arg(2)  // buffer
	length := uint32(ctx.Arg(3))
	retLen := ctx.Arg(4)
	const sdLen uint32 = 40 // SECURITY_DESCRIPTOR_RELATIVE minimal size
	if retLen != 0 {
		ctx.Mem.Write32(retLen, sdLen)
	}
	if secDesc == 0 {
		return StatusInvalidParameter
	}
	if length < sdLen {
		return StatusBufferTooSmall
	}
	// Absolute-like minimal descriptor compatible with our other SD helpers.
	ctx.Mem.Write8(secDesc+0, 1)  // Revision
	ctx.Mem.Write8(secDesc+1, 0)  // Sbz1
	ctx.Mem.Write16(secDesc+2, 0) // Control (no owner/group/dacl)
	ctx.Mem.Write64(secDesc+8, 0) // Owner
	ctx.Mem.Write64(secDesc+16, 0)
	ctx.Mem.Write64(secDesc+24, 0) // Group
	ctx.Mem.Write64(secDesc+32, 0) // DACL pointer/offset
	return StatusSuccess
}

func handleNtSetInformationObject(ctx *TrapContext) uint32 {
	h := Handle(ctx.Arg(0))
	infoClass := uint32(ctx.Arg(1))
	info := ctx.Arg(2)
	length := uint32(ctx.Arg(3))
	if ctx.Handles.Get(h) == nil {
		return StatusInvalidHandle
	}
	switch infoClass {
	case 4: // ObjectHandleFlagInformation
		if info == 0 || length < 2 {
			return StatusInvalidParameter
		}
		inherit, _ := ctx.Mem.Read8(info)
		protect, _ := ctx.Mem.Read8(info + 1)
		var f uint8
		if inherit != 0 {
			f |= 1
		}
		if protect != 0 {
			f |= 2
		}
		objectHandleFlags[h] = f
		return StatusSuccess
	default:
		return StatusNotImplemented
	}
}

func handleNtLockFile(ctx *TrapContext) uint32   { return StatusSuccess }
func handleNtUnlockFile(ctx *TrapContext) uint32 { return StatusSuccess }

func handleNtCreateMailslotFile(ctx *TrapContext) uint32 {
	// NtCreateMailslotFile(FileHandle*, DesiredAccess, ObjectAttributes*, IoStatusBlock*,
	//                      CreateOptions, MailslotQuota, MaximumMessageSize, ReadTimeout*)
	handlePtr := ctx.Arg(0)
	objAttr := ctx.Arg(2)
	ioStatus := ctx.Arg(3)
	maxMsg := uint32(ctx.Arg(6))
	readTimeoutPtr := ctx.Arg(7)

	name := ""
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}
	if name == "" {
		name = fmt.Sprintf(`\Device\Mailslot\mailslot-%d`, time.Now().UnixNano())
	}
	if maxMsg == 0 {
		maxMsg = 4096
	}
	var readTimeout uint32
	if readTimeoutPtr != 0 {
		if rt, err := ctx.Mem.Read64(readTimeoutPtr); err == nil {
			if int64(rt) < 0 {
				// Negative values are relative timeout in 100ns units.
				readTimeout = uint32((-int64(rt)) / 10000) // to ms
			}
		}
	}

	m := NewMailslot(name, maxMsg, readTimeout)
	RegisterMailslot(name, m)
	h := ctx.Handles.Alloc(m)
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	writeIOStatus(ctx.Mem, ioStatus, StatusSuccess, 0)
	return StatusSuccess
}

func handleNtCreateNamedPipeFile(ctx *TrapContext) uint32 {
	handlePtr := ctx.Arg(0)
	objAttr := ctx.Arg(2)
	var name string
	if objAttr != 0 {
		_, oaName, _, err := ReadObjectAttributes(ctx, objAttr)
		if err == nil {
			name = NormalizeObjectName(oaName)
		}
	}
	if name == "" {
		name = fmt.Sprintf("pipe-%d", time.Now().UnixNano())
	}
	pipe := NewServerPipe(name)
	RegisterNamedPipe(name, pipe)
	h, _ := ctx.Handles.AllocNamed(name, pipe)
	if handlePtr != 0 {
		ctx.Mem.Write64(handlePtr, uint64(h))
	}
	return StatusSuccess
}

// signalEventHandle signals a guest event handle if non-zero.
func signalEventHandle(ctx *TrapContext, handle uint64) {
	if handle == 0 {
		return
	}
	if eh, ok := ctx.Handles.Get(Handle(handle)).(*EventHandle); ok {
		eh.Set()
	}
}

func handleNtFsControlFile(ctx *TrapContext) uint32 {
	fileHandle := Handle(ctx.Arg(0))
	eventHandle := ctx.Arg(1)
	_ = ctx.Arg(2) // ApcRoutine
	_ = ctx.Arg(3) // ApcContext
	ioStatus := ctx.Arg(4)
	fsctlCode := uint32(ctx.Arg(5))
	_ = ctx.Arg(6) // InputBuffer
	_ = ctx.Arg(7) // InputBufferLength
	outputBuf := ctx.Arg(8)
	outputLen := uint32(ctx.Arg(9))

	if ctx.Trace {
		fmt.Printf("  NtFsControlFile: fsctl=0x%08x outLen=%d\n", fsctlCode, outputLen)
	}

	var status uint32 = StatusSuccess
	var info uint64
	pipe := ctx.Handles.GetNamedPipe(fileHandle)

	switch fsctlCode {
	case 0x00110000, 0x00110004, 0x00110008, 0x00110010, 0x00110018:
		// PIPE_ASSIGN_EVENT / DISCONNECT / LISTEN / QUERY_EVENT / WAIT
		if pipe == nil {
			status = StatusInvalidHandle
			break
		}
		if fsctlCode == 0x00110018 && outputBuf != 0 && outputLen >= 16 {
			avail := uint32(pipe.AvailableBytes())
			ctx.Mem.Write32(outputBuf, 0)        // pipe state
			ctx.Mem.Write32(outputBuf+4, avail)  // bytes available
			ctx.Mem.Write32(outputBuf+8, 0)      // number of messages
			ctx.Mem.Write32(outputBuf+12, avail) // message length
			info = 16
		}
	case 0x0011000C: // PIPE_PEEK
		if pipe == nil {
			status = StatusInvalidHandle
			break
		}
		if outputBuf != 0 && outputLen >= 16 {
			avail := uint32(pipe.AvailableBytes())
			ctx.Mem.Write32(outputBuf, 0)
			ctx.Mem.Write32(outputBuf+4, avail)
			ctx.Mem.Write32(outputBuf+8, 0)
			ctx.Mem.Write32(outputBuf+12, avail)
			info = 16
		}
	case 0x00110014: // PIPE_TRANSCEIVE
		if pipe == nil {
			status = StatusInvalidHandle
			break
		}
		inputBuf := ctx.Arg(6)
		inputLen := uint32(ctx.Arg(7))
		if inputBuf != 0 && inputLen > 0 {
			if data, err := ctx.Mem.ReadBytes(inputBuf, int(inputLen)); err == nil {
				_ = pipe.PipeWrite(data)
			}
		}
		if outputBuf != 0 && outputLen > 0 {
			buf := make([]byte, outputLen)
			n := pipe.PipeRead(buf)
			if n > 0 {
				ctx.Mem.WriteBytes(outputBuf, buf[:n])
			}
			info = uint64(n)
		}
	case 0x0009009C: // FSCTL_GET_COMPRESSION
		if outputBuf != 0 && outputLen >= 2 {
			ctx.Mem.Write16(outputBuf, 0) // COMPRESSION_FORMAT_NONE
			info = 2
		}

	case 0x000900A8: // FSCTL_GET_REPARSE_POINT
		status = 0xC0000275 // STATUS_NOT_A_REPARSE_POINT

	case 0x004D0008: // FSCTL_GET_NTFS_VOLUME_DATA
		status = 0xC0000010 // STATUS_INVALID_DEVICE_REQUEST

	case 0x00090028: // FSCTL_SET_COMPRESSION
		// Accept silently

	case 0x000900C0: // FSCTL_SET_SPARSE
		// Accept silently

	default:
		status = 0xC0000010 // STATUS_INVALID_DEVICE_REQUEST
		if ctx.Trace {
			fmt.Printf("  NtFsControlFile: unknown FSCTL 0x%08x\n", fsctlCode)
		}
	}

	writeIOStatus(ctx.Mem, ioStatus, status, info)
	signalEventHandle(ctx, eventHandle)
	return status
}

func handleNtPowerInformation(ctx *TrapContext) uint32 {
	infoLevel := uint32(ctx.Arg(0))
	_ = ctx.Arg(1) // input buffer
	_ = uint32(ctx.Arg(2))
	outBuf := ctx.Arg(3)
	outLen := uint32(ctx.Arg(4))

	switch infoLevel {
	case 0: // SystemPowerPolicyAc (best-effort, opaque)
		if outBuf != 0 && outLen >= 4 {
			ctx.Mem.Write32(outBuf, 0)
		}
		return StatusSuccess
	case 4: // SystemPowerCapabilities
		// Caller often expects a non-zeroed structure and success.
		if outBuf == 0 || outLen < 64 {
			return StatusBufferTooSmall
		}
		for i := uint32(0); i < outLen && i < 64; i++ {
			ctx.Mem.Write8(outBuf+uint64(i), 0)
		}
		ctx.Mem.Write8(outBuf+0, 1)  // PowerButtonPresent
		ctx.Mem.Write8(outBuf+1, 1)  // SleepButtonPresent
		ctx.Mem.Write8(outBuf+2, 1)  // LidPresent
		ctx.Mem.Write8(outBuf+8, 1)  // SystemS1
		ctx.Mem.Write8(outBuf+9, 1)  // SystemS2
		ctx.Mem.Write8(outBuf+10, 1) // SystemS3
		return StatusSuccess
	case 11: // SystemExecutionState
		if outBuf != 0 && outLen >= 4 {
			ctx.Mem.Write32(outBuf, 0)
		}
		return StatusSuccess
	case 12: // SystemPowerInformation
		if outBuf == 0 || outLen < 24 {
			return StatusBufferTooSmall
		}
		ctx.Mem.Write32(outBuf+0, 1) // MaxIdlenessAllowed
		ctx.Mem.Write32(outBuf+4, 1) // Idleness
		ctx.Mem.Write32(outBuf+8, 0) // TimeRemaining
		ctx.Mem.Write8(outBuf+12, 1) // CoolingMode
		return StatusSuccess
	case 5: // SystemBatteryState
		if outBuf == 0 || outLen < 32 {
			return StatusBufferTooSmall
		}
		for i := uint32(0); i < 32; i++ {
			ctx.Mem.Write8(outBuf+uint64(i), 0)
		}
		// AC online, no battery present (desktop-like behavior)
		ctx.Mem.Write8(outBuf+0, 1) // AcOnLine
		return StatusSuccess
	case 20: // ProcessorInformation
		if outBuf == 0 || outLen < 24 {
			return StatusBufferTooSmall
		}
		// Minimal 1-processor entry
		ctx.Mem.Write32(outBuf+0, 0)    // Number
		ctx.Mem.Write32(outBuf+4, 60)   // MaxMhz
		ctx.Mem.Write32(outBuf+8, 35)   // CurrentMhz
		ctx.Mem.Write32(outBuf+12, 100) // MhzLimit
		ctx.Mem.Write32(outBuf+16, 0)   // MaxIdleState
		ctx.Mem.Write32(outBuf+20, 0)   // CurrentIdleState
		return StatusSuccess
	default:
		return StatusNotImplemented
	}
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
	// RtlTimeFieldsToTime(TIME_FIELDS* tf, LARGE_INTEGER* time)
	tf := ctx.Arg(0)
	out := ctx.Arg(1)
	if tf == 0 || out == 0 {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	yr, _ := ctx.Mem.Read16(tf + 0)
	mo, _ := ctx.Mem.Read16(tf + 2)
	dy, _ := ctx.Mem.Read16(tf + 4)
	hr, _ := ctx.Mem.Read16(tf + 6)
	mi, _ := ctx.Mem.Read16(tf + 8)
	se, _ := ctx.Mem.Read16(tf + 10)
	ms, _ := ctx.Mem.Read16(tf + 12)
	t := time.Date(int(yr), time.Month(mo), int(dy), int(hr), int(mi), int(se), int(ms)*1e6, time.UTC)
	ft := uint64(t.UnixNano()/100 + 116444736000000000)
	ctx.Mem.Write64(out, ft)
	ctx.SetReturn(1) // TRUE
	return StatusSuccess
}

func handleRtlTimeToTimeFields(ctx *TrapContext) uint32 {
	// RtlTimeToTimeFields(LARGE_INTEGER* time, TIME_FIELDS* tf)
	timePtr := ctx.Arg(0)
	tf := ctx.Arg(1)
	if timePtr == 0 || tf == 0 {
		return StatusSuccess
	}
	ft, _ := ctx.Mem.Read64(timePtr)
	ns := (int64(ft) - 116444736000000000) * 100
	t := time.Unix(0, ns).UTC()
	ctx.Mem.Write16(tf+0, uint16(t.Year()))
	ctx.Mem.Write16(tf+2, uint16(t.Month()))
	ctx.Mem.Write16(tf+4, uint16(t.Day()))
	ctx.Mem.Write16(tf+6, uint16(t.Hour()))
	ctx.Mem.Write16(tf+8, uint16(t.Minute()))
	ctx.Mem.Write16(tf+10, uint16(t.Second()))
	ctx.Mem.Write16(tf+12, uint16(t.Nanosecond()/1e6))
	ctx.Mem.Write16(tf+14, uint16(t.Weekday()))
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
		for i := uint64(0); i < 40; i++ {
			ctx.Mem.Write8(sd+i, 0)
		}
		ctx.Mem.Write8(sd, 1)    // Revision
		ctx.Mem.Write16(sd+2, 0) // Control
	}
	return StatusSuccess
}

func handleRtlSetDaclSecurityDescriptor(ctx *TrapContext) uint32 {
	sd := ctx.Arg(0)
	present := ctx.Arg(1) != 0
	dacl := ctx.Arg(2)
	defaulted := ctx.Arg(3) != 0
	if sd != 0 {
		control, _ := ctx.Mem.Read16(sd + 2)
		control &^= 0x0004 | 0x0008
		if present {
			control |= 0x0004
			ctx.Mem.Write64(sd+28, dacl)
		} else {
			ctx.Mem.Write64(sd+28, 0)
		}
		if defaulted {
			control |= 0x0008
		}
		ctx.Mem.Write16(sd+2, control)
	}
	return StatusSuccess
}

func handleRtlGetDaclSecurityDescriptor(ctx *TrapContext) uint32 {
	sd := ctx.Arg(0)
	pbPresent := ctx.Arg(1)
	ppDacl := ctx.Arg(2)
	pbDefaulted := ctx.Arg(3)
	if pbPresent != 0 {
		present := uint32(0)
		if sd != 0 {
			control, _ := ctx.Mem.Read16(sd + 2)
			if control&0x0004 != 0 {
				present = 1
			}
		}
		ctx.Mem.Write32(pbPresent, present)
	}
	if ppDacl != 0 {
		var dacl uint64
		if sd != 0 {
			dacl, _ = ctx.Mem.Read64(sd + 28)
		}
		ctx.Mem.Write64(ppDacl, dacl)
	}
	if pbDefaulted != 0 {
		defaulted := uint32(0)
		if sd != 0 {
			control, _ := ctx.Mem.Read16(sd + 2)
			if control&0x0008 != 0 {
				defaulted = 1
			}
		}
		ctx.Mem.Write32(pbDefaulted, defaulted)
	}
	return StatusSuccess
}

func handleRtlCreateAcl(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlAddAccessAllowedAce(ctx *TrapContext) uint32   { return StatusSuccess }
func handleRtlAddAccessAllowedAceEx(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlAllocateAndInitializeSid(ctx *TrapContext) uint32 {
	sidPtr := ctx.Arg(0)
	if sidPtr != 0 {
		sid := ctx.Mem.Mmap(0, 28, mmu.PermRead|mmu.PermWrite)
		ctx.Mem.Write8(sid, 1)   // Revision
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
func handleRtlActivateActivationContext(ctx *TrapContext) uint32   { return StatusSuccess }
func handleRtlDeactivateActivationContext(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlGetActiveActivationContext(ctx *TrapContext) uint32 {
	cookie := ctx.Arg(0)
	if cookie != 0 {
		ctx.Mem.Write64(cookie, 0)
	}
	return StatusSuccess
}
func handleRtlAddRefActivationContext(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlReleaseActivationContext(ctx *TrapContext) uint32   { return StatusSuccess }
func handleRtlCreateActivationContext(ctx *TrapContext) uint32    { return StatusSuccess }
func handleRtlZombifyActivationContext(ctx *TrapContext) uint32   { return StatusSuccess }
func handleRtlFreeActivationContextStack(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlQueryInformationActivationContext(ctx *TrapContext) uint32 {
	// RtlQueryInformationActivationContext(Flags, ActCtx, SubInst, Class, Buffer, BufSize, RetLen)
	_ = ctx.Arg(0) // flags
	_ = ctx.Arg(1) // activation context handle
	_ = ctx.Arg(2) // sub instance index
	infoClass := uint32(ctx.Arg(3))
	buf := ctx.Arg(4)
	bufSize := uint32(ctx.Arg(5))
	retLen := ctx.Arg(6)

	var needed uint32
	switch infoClass {
	case 1: // ActivationContextBasicInformation
		needed = 16
	case 2: // ActivationContextDetailedInformation
		needed = 32
	default:
		return StatusNotImplemented
	}
	if retLen != 0 {
		ctx.Mem.Write32(retLen, needed)
	}
	if buf == 0 || bufSize < needed {
		return StatusBufferTooSmall
	}
	for i := uint32(0); i < needed; i++ {
		ctx.Mem.Write8(buf+uint64(i), 0)
	}
	return StatusSuccess
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

func handleRtlDeleteTimer(ctx *TrapContext) uint32 { return StatusSuccess }
func handleRtlUpdateTimer(ctx *TrapContext) uint32 { return StatusSuccess }
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
func handleRtlDeregisterWait(ctx *TrapContext) uint32   { return StatusSuccess }
func handleRtlDeregisterWaitEx(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlSetIoCompletionCallback(ctx *TrapContext) uint32 { return StatusSuccess }

func handleRtlGUIDFromString(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlFindMessage(ctx *TrapContext) uint32 {
	// RtlFindMessage(Base, Type, LangId, MsgId, MessageEntry**)
	_ = ctx.Arg(0)
	_ = ctx.Arg(1)
	_ = ctx.Arg(2)
	_ = ctx.Arg(3)
	entryOut := ctx.Arg(4)
	if entryOut == 0 {
		return StatusInvalidParameter
	}
	// MESSAGE_RESOURCE_ENTRY: Length(2), Flags(2), Text[]
	msg := []byte("stub message\x00")
	entry := ctx.Mem.Mmap(0, uint64(4+len(msg)), mmu.PermRead|mmu.PermWrite)
	ctx.Mem.Write16(entry+0, uint16(4+len(msg)))
	ctx.Mem.Write16(entry+2, 0) // ANSI
	ctx.Mem.WriteBytes(entry+4, msg)
	ctx.Mem.Write64(entryOut, entry)
	return StatusSuccess
}

func handleRtlFormatMessage(ctx *TrapContext) uint32 {
	// Best-effort formatter: copy source WCHAR string to destination.
	src := ctx.Arg(0) // PWSTR source
	_ = ctx.Arg(1)    // width
	_ = ctx.Arg(2)    // ignore inserts
	_ = ctx.Arg(3)    // arguments
	dst := ctx.Arg(4) // PWSTR destination
	dstBytes := uint32(ctx.Arg(5))
	retLen := ctx.Arg(6)
	if src == 0 || dst == 0 || dstBytes < 2 {
		return StatusInvalidParameter
	}
	text := readGuestStringUTF16(ctx.Mem, src, 4096)
	if text == "" {
		ctx.Mem.Write16(dst, 0)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 0)
		}
		return StatusSuccess
	}
	utf16b := encodeUTF16LE(text)
	maxCopy := int(dstBytes - 2)
	if maxCopy < 0 {
		maxCopy = 0
	}
	if len(utf16b) > maxCopy {
		utf16b = utf16b[:maxCopy]
	}
	ctx.Mem.WriteBytes(dst, utf16b)
	ctx.Mem.Write16(dst+uint64(len(utf16b)), 0)
	if retLen != 0 {
		ctx.Mem.Write32(retLen, uint32(len(utf16b)))
	}
	return StatusSuccess
}

func minUint32(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
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

func handleNtNotifyChangeKey(ctx *TrapContext) uint32           { return StatusSuccess }
func handleNtNotifyChangeDirectoryFile(ctx *TrapContext) uint32 { return StatusSuccess }

// Etw stubs
func handleEtwEventRegister(ctx *TrapContext) uint32   { return StatusSuccess }
func handleEtwEventUnregister(ctx *TrapContext) uint32 { return StatusSuccess }
func handleEtwEventWrite(ctx *TrapContext) uint32      { return StatusSuccess }
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

func handleRtlWow64EnableFsRedirection(ctx *TrapContext) uint32   { return StatusSuccess }
func handleRtlWow64EnableFsRedirectionEx(ctx *TrapContext) uint32 { return StatusSuccess }

// handleLdrDisableThreadCalloutsForDll disables DLL_THREAD_ATTACH/DETACH notifications.
func handleLdrDisableThreadCalloutsForDll(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // STATUS_SUCCESS
	return StatusSuccess
}

// handleLdrFindResource_U navigates the PE resource directory tree.
// LdrFindResource_U(HMODULE hModule, LDR_RESOURCE_INFO *info, ULONG level, IMAGE_RESOURCE_DATA_ENTRY **entry)
func handleLdrFindResource_U(ctx *TrapContext) uint32 {
	hModule := ctx.Arg(0)  // module base address
	infoPtr := ctx.Arg(1)  // LDR_RESOURCE_INFO*
	level := ctx.Arg(2)    // number of levels (typically 3)
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
	rva, _ = mem.Read32(optHdr + 0x70 + 2*8)      // resource dir RVA
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
var objectHandleFlags = map[Handle]uint8{} // bit0=inherit, bit1=protect from close

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
	atom := uint32(ctx.Arg(0))
	infoClass := uint32(ctx.Arg(1))
	outBuf := ctx.Arg(2)
	outLen := uint32(ctx.Arg(3))
	retLen := ctx.Arg(4)

	var atomName string
	for k, v := range atomTable {
		if v == atom {
			atomName = k
			break
		}
	}
	if atomName == "" {
		return StatusObjectNameNotFound
	}

	switch infoClass {
	case 0: // AtomBasicInformation
		nameUTF16 := encodeUTF16LE(atomName)
		needed := uint32(8 + len(nameUTF16))
		if retLen != 0 {
			ctx.Mem.Write32(retLen, needed)
		}
		if outBuf == 0 || outLen < needed {
			return StatusBufferTooSmall
		}
		ctx.Mem.Write16(outBuf+0, uint16(atom))           // Atom
		ctx.Mem.Write16(outBuf+2, uint16(len(nameUTF16))) // NameLength (bytes)
		ctx.Mem.Write16(outBuf+4, 1)                      // UsageCount
		ctx.Mem.Write16(outBuf+6, 0)                      // Flags
		ctx.Mem.WriteBytes(outBuf+8, nameUTF16)           // Name
		return StatusSuccess
	case 1: // AtomTableInformation (minimal)
		if retLen != 0 {
			ctx.Mem.Write32(retLen, 4)
		}
		if outBuf == 0 || outLen < 4 {
			return StatusBufferTooSmall
		}
		ctx.Mem.Write32(outBuf, uint32(len(atomTable)))
		return StatusSuccess
	default:
		return StatusNotImplemented
	}
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
	// param1 := ctx.Arg(0)
	// param2 := ctx.Arg(1)
	// code := ctx.Arg(2)
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

// ──────────────────────────────────────────────────────────
// Wave 10: RtlEncodePointer / RtlDecodePointer
// Windows Vista+ uses a per-process cookie XOR to encode pointers
// stored in function pointer tables (CRT uses this heavily).
// Reference: wine/dlls/ntdll/misc.c, reactos/lib/rtl/process.c
// ──────────────────────────────────────────────────────────

// processCookie is a process-wide random value used for pointer encoding.
// In Windows it is stored at PEB+0x700, but for HLE purposes we keep it here.
var processCookie = func() uint64 {
	var b [8]byte
	unix.Getrandom(b[:], 0)
	v := uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
	if v == 0 {
		v = 0xDEADBEEFCAFEBABE
	}
	return v
}()

func handleRtlEncodePointer(ctx *TrapContext) uint32 {
	ptr := ctx.Arg(0)
	ctx.SetReturn(ptr ^ processCookie)
	return StatusSuccess
}

func handleRtlDecodePointer(ctx *TrapContext) uint32 {
	ptr := ctx.Arg(0)
	ctx.SetReturn(ptr ^ processCookie)
	return StatusSuccess
}

func handleRtlEncodeSystemPointer(ctx *TrapContext) uint32 {
	ptr := ctx.Arg(0)
	ctx.SetReturn(ptr ^ processCookie)
	return StatusSuccess
}

func handleRtlDecodeSystemPointer(ctx *TrapContext) uint32 {
	ptr := ctx.Arg(0)
	ctx.SetReturn(ptr ^ processCookie)
	return StatusSuccess
}

// ──────────────────────────────────────────────────────────
// NtTerminateThread - terminate a specific thread
// Reference: reactos/ntoskrnl/ps/kill.c
// ──────────────────────────────────────────────────────────
func handleNtTerminateThread(ctx *TrapContext) uint32 {
	// NtTerminateThread(ThreadHandle, ExitStatus)
	// ThreadHandle == NULL or current thread → exit the process (single-threaded HLE)
	hThread := ctx.Arg(0)
	exitCode := uint32(ctx.Arg(1))
	_ = hThread
	// In single-threaded HLE, terminating any thread terminates the process
	os.Exit(int(exitCode))
	return StatusSuccess
}

// ──────────────────────────────────────────────────────────
// NtCreateJobObject / NtOpenJobObject / NtAssignProcessToJobObject
// Reference: reactos/ntoskrnl/ps/job.c
// ──────────────────────────────────────────────────────────
func handleNtCreateJobObject(ctx *TrapContext) uint32 {
	outHandle := ctx.Arg(0)
	// arg1=DesiredAccess, arg2=ObjectAttributes
	name := ""
	j := NewJobHandle(name)
	h := ctx.Handles.Alloc(j)
	if outHandle != 0 {
		ctx.Mem.Write64(outHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtOpenJobObject(ctx *TrapContext) uint32 {
	outHandle := ctx.Arg(0)
	j := NewJobHandle("")
	h := ctx.Handles.Alloc(j)
	if outHandle != 0 {
		ctx.Mem.Write64(outHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtAssignProcessToJobObject(ctx *TrapContext) uint32 {
	hJob := Handle(ctx.Arg(0))
	// hProcess := Handle(ctx.Arg(1))
	j := ctx.Handles.GetJob(hJob)
	if j != nil {
		j.AddProcess(ctx.State.ProcessId)
	}
	return StatusSuccess
}

func handleNtQueryInformationJobObject(ctx *TrapContext) uint32 {
	// NtQueryInformationJobObject(JobHandle, InfoClass, Info, InfoLen, ReturnLen*)
	// Class 1 = JobObjectBasicAccountingInformation - return zeros (no limits)
	infoPtr := ctx.Arg(2)
	infoLen := ctx.Arg(3)
	retLen := ctx.Arg(4)
	if infoPtr != 0 && infoLen > 0 {
		for i := uint64(0); i < infoLen; i++ {
			ctx.Mem.Write8(infoPtr+i, 0)
		}
	}
	if retLen != 0 {
		ctx.Mem.Write32(retLen, uint32(infoLen))
	}
	return StatusSuccess
}

// ──────────────────────────────────────────────────────────
// NtCreateThread / NtCreateThreadEx (stub - Raven is single-threaded for now)
// Reference: reactos/ntoskrnl/ps/thread.c
// ──────────────────────────────────────────────────────────
func handleNtCreateThread(ctx *TrapContext) uint32 {
	// NtCreateThread(ThreadHandle*, Access, ObjAttr*, ProcessHandle,
	//
	//	ClientId*, ThreadContext*, InitialTeb*, Suspended)
	//
	// We don't support true multi-threaded guests; return a pseudo-handle.
	outHandle := ctx.Arg(0)
	tid := 1
	if ctx.State != nil && ctx.State.ThreadId != 0 {
		tid = int(ctx.State.ThreadId)
	}
	h := ctx.Handles.Alloc(&ThreadHandle{
		TID:      tid,
		Done:     make(chan struct{}),
		Priority: 8,
	})
	if outHandle != 0 {
		ctx.Mem.Write64(outHandle, uint64(h))
	}
	return StatusSuccess
}

func handleNtCreateThreadEx(ctx *TrapContext) uint32 {
	outHandle := ctx.Arg(0)
	tid := 1
	if ctx.State != nil && ctx.State.ThreadId != 0 {
		tid = int(ctx.State.ThreadId)
	}
	h := ctx.Handles.Alloc(&ThreadHandle{
		TID:      tid,
		Done:     make(chan struct{}),
		Priority: 8,
	})
	if outHandle != 0 {
		ctx.Mem.Write64(outHandle, uint64(h))
	}
	return StatusSuccess
}

// ──────────────────────────────────────────────────────────
// NtSetTimerEx - extended timer with flags
// ──────────────────────────────────────────────────────────
func handleNtSetTimerEx(ctx *TrapContext) uint32 {
	return handleNtSetTimer(ctx)
}

// ──────────────────────────────────────────────────────────
// RtlAddFunctionTable / RtlInstallFunctionTableCallback / RtlDeleteFunctionTable
// Used by MSVC for x64 exception handling (SEH) - we return TRUE (registered).
// Reference: wine/dlls/ntdll/unwind.c
// ──────────────────────────────────────────────────────────
func handleRtlAddFunctionTable(ctx *TrapContext) uint32 {
	if AddDynamicFunctionTable(ctx.Mem, ctx.Arg(0), uint32(ctx.Arg(1)), ctx.Arg(2)) {
		ctx.SetReturn(1)
	} else {
		ctx.SetReturn(0)
	}
	return StatusSuccess
}

func handleRtlInstallFunctionTableCallback(ctx *TrapContext) uint32 {
	if InstallDynamicFunctionTableCallback(ctx.Arg(0), ctx.Arg(1), ctx.Arg(2), ctx.Arg(3), ctx.Arg(4)) {
		ctx.SetReturn(1)
	} else {
		ctx.SetReturn(0)
	}
	return StatusSuccess
}

func handleRtlDeleteFunctionTable(ctx *TrapContext) uint32 {
	if DeleteDynamicFunctionTable(ctx.Arg(0)) {
		ctx.SetReturn(1)
	} else {
		ctx.SetReturn(0)
	}
	return StatusSuccess
}

func handleRtlAddGrowableFunctionTable(ctx *TrapContext) uint32 {
	ctx.SetReturn(0) // STATUS_SUCCESS
	return StatusSuccess
}

func handleRtlGrowFunctionTable(ctx *TrapContext) uint32 {
	return StatusSuccess
}

func handleRtlDeleteGrowableFunctionTable(ctx *TrapContext) uint32 {
	return StatusSuccess
}

// ──────────────────────────────────────────────────────────
// RtlVirtualUnwind - x64 SEH virtual unwind
// Reference: wine/dlls/ntdll/signal_x86_64.c
// ──────────────────────────────────────────────────────────
func handleRtlVirtualUnwind(ctx *TrapContext) uint32 {
	contextRecord, err := ReadAMD64Context(ctx.Mem, ctx.Arg(4))
	if err != nil {
		ctx.SetReturn(0)
		return StatusSuccess
	}
	functionEntry := ReadRuntimeFunctionEntry(ctx.Mem, ctx.Arg(3))
	if functionEntry == nil {
		trampoline := AllocTrampoline(ctx.Mem)
		guestCall := func(addr uint64, args []uint64) (uint64, error) {
			return CallGuestFunction(ctx.CPU, ctx.Mem, trampoline, addr, args, ctx.Trace)
		}
		functionEntry, _, _ = LookupFunctionEntry(ctx.Mem, ctx.Arg(2), guestCall)
	}
	handlerAddr, handlerData, establisherFrame, err := VirtualUnwind(
		ctx.Mem,
		uint32(ctx.Arg(0)),
		ctx.Arg(1),
		ctx.Arg(2),
		functionEntry,
		contextRecord,
	)
	if err == nil {
		_ = WriteAMD64Context(ctx.Mem, ctx.Arg(4), contextRecord)
		if ctx.Arg(5) != 0 {
			ctx.Mem.Write64(ctx.Arg(5), handlerData)
		}
		if ctx.Arg(6) != 0 {
			ctx.Mem.Write64(ctx.Arg(6), establisherFrame)
		}
	}
	ctx.SetReturn(handlerAddr)
	return StatusSuccess
}

// ──────────────────────────────────────────────────────────
// NtAreMappedFilesTheSame
// ──────────────────────────────────────────────────────────
func handleNtAreMappedFilesTheSame(ctx *TrapContext) uint32 {
	if ctx.Arg(0) == ctx.Arg(1) {
		return StatusSuccess
	}
	return 0xC0000002 // STATUS_NOT_SAME_DEVICE
}

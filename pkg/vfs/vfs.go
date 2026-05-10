package vfs

import (
	"crypto/rand"
	"errors"
	"fmt"
	iofs "io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var ErrInvalidPathAlias = errors.New("path aliases another replace operand")
var ErrRenameParentNotFound = errors.New("rename destination parent is unavailable")

// RenameCommitResult controls how RenameatWithCommit updates the source entry.
type RenameCommitResult struct {
	KeepSource bool
}

// RenameCommitSource describes the source while the VFS lock is held.
type RenameCommitSource struct {
	Data  []byte
	IsDir bool
}

// RenameOptions controls replacement rules for a VFS rename.
type RenameOptions struct {
	ReplaceExisting         bool
	RejectExistingDirectory bool
}

// FileMode represents virtual file permissions.
type FileMode uint32

const (
	ModeRead  FileMode = 1 << 0
	ModeWrite FileMode = 1 << 1
)

// Inode types
const (
	S_IFMT  uint32 = 0xF000
	S_IFDIR uint32 = 0x4000
	S_IFCHR uint32 = 0x2000
	S_IFREG uint32 = 0x8000
	S_IFIFO uint32 = 0x1000
	S_IFLNK uint32 = 0xA000
)

// Open flags
const (
	O_RDONLY = 0
	O_WRONLY = 1
	O_RDWR   = 2
	O_CREAT  = 0x40
	O_TRUNC  = 0x200
	O_APPEND = 0x400
)

// Seek whence
const (
	SEEK_SET = 0
	SEEK_CUR = 1
	SEEK_END = 2
)

var inodeCounter uint64

func nextInode() uint64 {
	return atomic.AddUint64(&inodeCounter, 1)
}

// VNode is an in-memory file or directory.
type VNode struct {
	Name     string
	IsDir    bool
	Data     []byte
	Children map[string]*VNode
	Mode     FileMode
	Ino      uint64
	Nlink    uint32
	Uid      uint32
	Gid      uint32
	FileMode uint32 // S_IFXXX | permission bits
	Size     int64
	Atime    time.Time
	Mtime    time.Time
	Ctime    time.Time
	// For symlinks
	LinkTarget string
}

func newVNode(name string, isDir bool) *VNode {
	now := time.Now()
	mode := uint32(0755)
	if isDir {
		mode = S_IFDIR | 0755
	} else {
		mode = S_IFREG | 0644
	}
	return &VNode{
		Name:     name,
		IsDir:    isDir,
		Ino:      nextInode(),
		Nlink:    1,
		Uid:      1000,
		Gid:      1000,
		FileMode: mode,
		Atime:    now,
		Mtime:    now,
		Ctime:    now,
		Children: make(map[string]*VNode),
	}
}

// FD is an open file descriptor in the guest.
type FD struct {
	Node     *VNode
	Offset   int64
	Flags    int
	PipeR    *PipeEnd       // non-nil if this fd is a pipe read end
	PipeW    *PipeEnd       // non-nil if this fd is a pipe write end
	Socket   *SocketFD      // non-nil for AF_UNIX sockets
	HostFile *os.File       // non-nil when backed by a real host FD (memfd, etc.)
	Epoll    *EpollInstance // non-nil for epoll instances
	EventFD  *EventFD       // non-nil for eventfd descriptors
}

// PipeEnd is one end of a virtual pipe.
type PipeEnd struct {
	mu     sync.Mutex
	buf    []byte
	closed bool
}

func (p *PipeEnd) Write(data []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, fmt.Errorf("broken pipe")
	}
	p.buf = append(p.buf, data...)
	return len(data), nil
}

func (p *PipeEnd) Read(buf []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.buf) == 0 {
		if p.closed {
			return 0, nil // EOF
		}
		return 0, nil // would block - return 0 for now
	}
	n := copy(buf, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

func (p *PipeEnd) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
}

// VFS is a virtual filesystem with file descriptor table.
type VFS struct {
	mu      sync.Mutex
	root    *VNode
	fds     map[int]*FD
	nextFD  int
	HostOut func(fd int, data []byte)    // callback for stdout/stderr
	HostIn  func(fd int, buf []byte) int // callback for stdin
	ElfPath string                       // path to loaded binary (for /proc/self/exe)
	Cwd     string                       // current working directory
}

// New creates a VFS with an empty root and pre-opened stdin/stdout/stderr.
func New() *VFS {
	root := newVNode("/", true)
	fs := &VFS{
		root:   root,
		fds:    make(map[int]*FD),
		nextFD: 3,
		Cwd:    "/",
	}

	// Reserve fd 0 (stdin), 1 (stdout), 2 (stderr)
	stdinNode := newVNode("stdin", false)
	stdinNode.FileMode = S_IFCHR | 0666
	stdoutNode := newVNode("stdout", false)
	stdoutNode.FileMode = S_IFCHR | 0666
	stderrNode := newVNode("stderr", false)
	stderrNode.FileMode = S_IFCHR | 0666

	fs.fds[0] = &FD{Node: stdinNode, Flags: O_RDONLY}
	fs.fds[1] = &FD{Node: stdoutNode, Flags: O_WRONLY}
	fs.fds[2] = &FD{Node: stderrNode, Flags: O_WRONLY}

	// Create /proc/self directory
	fs.initProcFS()
	// Create /dev directory
	fs.initDevFS()
	// Create /tmp directory
	fs.MkdirAll("/tmp")

	return fs
}

func (v *VFS) initProcFS() {
	v.MkdirAll("/proc/self")
	// /proc/self/exe is a symlink - handled specially in Readlinkat
}

func (v *VFS) initDevFS() {
	v.MkdirAll("/dev")
	// /dev/null
	null := newVNode("null", false)
	null.FileMode = S_IFCHR | 0666
	v.root.Children["dev"].Children["null"] = null
	// /dev/zero
	zero := newVNode("zero", false)
	zero.FileMode = S_IFCHR | 0666
	v.root.Children["dev"].Children["zero"] = zero
	// /dev/urandom
	urandom := newVNode("urandom", false)
	urandom.FileMode = S_IFCHR | 0666
	v.root.Children["dev"].Children["urandom"] = urandom
	// /dev/shm
	v.MkdirAll("/dev/shm")
}

// MkdirAll creates a directory path and all parents.
func (v *VFS) MkdirAll(path string) {
	v.mu.Lock()
	defer v.mu.Unlock()

	parts := SplitAll(path)
	cur := v.root
	for _, p := range parts {
		if child, ok := cur.Children[p]; ok {
			cur = child
			continue
		}
		nd := newVNode(p, true)
		cur.Children[p] = nd
		cur = nd
	}
}

// CreateFile creates a file at the given path with data.
func (v *VFS) CreateFile(path string, data []byte, mode FileMode) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	dir, name := SplitPath(path)
	parent, err := v.Resolve(dir)
	if err != nil {
		return err
	}
	if !parent.IsDir {
		return fmt.Errorf("not a directory: %s", dir)
	}
	nd := newVNode(name, false)
	nd.Data = append([]byte(nil), data...)
	nd.Size = int64(len(data))
	nd.Mode = mode
	parent.Children[name] = nd
	return nil
}

type virtualFileInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (i virtualFileInfo) Name() string       { return i.name }
func (i virtualFileInfo) Size() int64        { return i.size }
func (i virtualFileInfo) Mode() os.FileMode  { return i.mode }
func (i virtualFileInfo) ModTime() time.Time { return i.modTime }
func (i virtualFileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i virtualFileInfo) Sys() any           { return nil }

func virtualDirEntry(node *VNode) os.DirEntry {
	mode := os.FileMode(node.FileMode & 0777)
	switch node.FileMode & S_IFMT {
	case S_IFDIR:
		mode |= os.ModeDir
	case S_IFLNK:
		mode |= os.ModeSymlink
	case S_IFCHR:
		mode |= os.ModeDevice | os.ModeCharDevice
	case S_IFIFO:
		mode |= os.ModeNamedPipe
	}
	return iofs.FileInfoToDirEntry(virtualFileInfo{
		name:    node.Name,
		size:    node.Size,
		mode:    mode,
		modTime: node.Mtime,
	})
}

func caseCorrectHostPath(path string) string {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return clean
	}

	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(clean, current), current) {
		hostEntries, err := os.ReadDir(current)
		if err != nil {
			return clean
		}
		actual := ""
		for _, entry := range hostEntries {
			if entry.Name() == part {
				actual = entry.Name()
				break
			}
			if actual == "" && strings.EqualFold(entry.Name(), part) {
				actual = entry.Name()
			}
		}
		if actual == "" {
			return clean
		}
		current = filepath.Join(current, actual)
	}
	return current
}

// ReadDir returns a merged snapshot of virtual and host-backed entries.
func (v *VFS) ReadDir(path string) ([]os.DirEntry, error) {
	v.mu.Lock()
	absPath := v.ResolvePath(-100, path)
	node, virtualErr := v.Resolve(absPath)
	entries := make(map[string]os.DirEntry)
	if virtualErr == nil {
		if !node.IsDir {
			v.mu.Unlock()
			return nil, fmt.Errorf("not a directory: %s", absPath)
		}
		for _, child := range node.Children {
			entries[strings.ToLower(child.Name)] = virtualDirEntry(child)
		}
	}
	v.mu.Unlock()

	hostEntries, hostErr := os.ReadDir(caseCorrectHostPath(absPath))
	for _, entry := range hostEntries {
		key := strings.ToLower(entry.Name())
		if _, exists := entries[key]; !exists {
			entries[key] = entry
		}
	}
	if virtualErr != nil && hostErr != nil {
		return nil, virtualErr
	}

	result := make([]os.DirEntry, 0, len(entries))
	for _, entry := range entries {
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		return strings.ToLower(result[i].Name()) < strings.ToLower(result[j].Name())
	})
	return result, nil
}

// Mkdir creates a directory.
func (v *VFS) Mkdir(path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	dir, name := SplitPath(path)
	parent, err := v.Resolve(dir)
	if err != nil {
		return err
	}
	nd := newVNode(name, true)
	parent.Children[name] = nd
	return nil
}

// OpenAt opens a file relative to a dirfd.
// dirfd is AT_FDCWD (-100) for CWD-relative, or an fd for a directory.
func (v *VFS) OpenAt(dirfd int, path string, flags int, mode uint32) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	// Resolve path
	absPath := v.ResolvePath(dirfd, path)

	// Check for special device paths
	if absPath == "/dev/null" || absPath == "/dev/zero" || absPath == "/dev/urandom" {
		node, err := v.Resolve(absPath)
		if err != nil {
			return -1, err
		}
		fd := v.nextFD
		v.nextFD++
		v.fds[fd] = &FD{Node: node, Flags: flags}
		return fd, nil
	}

	node, err := v.Resolve(absPath)
	if err != nil {
		// Keep creation inside the VFS when its parent is a virtual directory.
		if flags&O_CREAT != 0 {
			dir, name := SplitPath(absPath)
			if parent, perr := v.Resolve(dir); perr == nil {
				nd := newVNode(name, false)
				nd.FileMode = S_IFREG | mode
				parent.Children[name] = nd
				fd := v.nextFD
				v.nextFD++
				v.fds[fd] = &FD{Node: nd, Flags: flags}
				return fd, nil
			}
		}

		// Host passthrough for system libraries, config, and runtime files
		hostPassthrough := strings.HasPrefix(absPath, "/lib") ||
			strings.HasPrefix(absPath, "/usr") ||
			strings.HasPrefix(absPath, "/etc") ||
			strings.HasPrefix(absPath, "/run/") ||
			strings.HasPrefix(absPath, "/home/") ||
			strings.HasPrefix(absPath, "/tmp/") ||
			strings.HasPrefix(absPath, "/sys/") ||
			strings.HasPrefix(absPath, "/proc/")
		if hostPassthrough {
			hostFlags := os.O_RDONLY
			if flags&O_WRONLY != 0 {
				hostFlags = os.O_WRONLY
			} else if flags&O_RDWR != 0 {
				hostFlags = os.O_RDWR
			}
			if flags&O_CREAT != 0 {
				hostFlags |= os.O_CREATE
			}
			if flags&O_TRUNC != 0 {
				hostFlags |= os.O_TRUNC
			}
			if flags&O_APPEND != 0 {
				hostFlags |= os.O_APPEND
			}
			if f, oerr := os.OpenFile(absPath, hostFlags, os.FileMode(mode)); oerr == nil {
				fd := v.nextFD
				v.nextFD++
				v.fds[fd] = &FD{HostFile: f, Flags: flags}
				return fd, nil
			}
		}

		return -1, err
	}

	if flags&O_TRUNC != 0 && !node.IsDir {
		node.Data = nil
		node.Size = 0
	}

	fd := v.nextFD
	v.nextFD++
	v.fds[fd] = &FD{Node: node, Flags: flags}
	return fd, nil
}

// Open opens a file and returns a virtual FD number.
func (v *VFS) Open(path string, flags int) (int, error) {
	return v.OpenAt(-100, path, flags, 0644)
}

// FileBytes reads all bytes of a VFS file at the given path.
func (v *VFS) FileBytes(path string) ([]byte, error) {
	fd, err := v.Open(path, O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer v.Close(fd)
	v.mu.Lock()
	f, ok := v.fds[fd]
	v.mu.Unlock()
	if !ok || f.Node == nil {
		return nil, fmt.Errorf("no data for %q", path)
	}
	out := make([]byte, len(f.Node.Data))
	copy(out, f.Node.Data)
	return out, nil
}

// Read reads up to len(buf) bytes from fd.
func (v *VFS) Read(fd int, buf []byte) (int, error) {
	v.mu.Lock()
	f, ok := v.fds[fd]
	if !ok {
		v.mu.Unlock()
		return -1, fmt.Errorf("bad fd %d", fd)
	}
	v.mu.Unlock()

	// Special: stdin
	if fd == 0 && v.HostIn != nil {
		return v.HostIn(fd, buf), nil
	}

	// EventFD read
	if f.EventFD != nil {
		return f.EventFD.Read(buf)
	}

	// Socket read
	if f.Socket != nil {
		return f.Socket.Read(buf)
	}

	// Host file read (memfd etc.)
	if f.HostFile != nil {
		return f.HostFile.Read(buf)
	}

	// Pipe read end
	if f.PipeR != nil {
		return f.PipeR.Read(buf)
	}

	// Special devices
	if f.Node != nil {
		if f.Node.Name == "null" {
			return 0, nil // EOF
		}
		if f.Node.Name == "zero" {
			for i := range buf {
				buf[i] = 0
			}
			return len(buf), nil
		}
		if f.Node.Name == "urandom" {
			rand.Read(buf)
			return len(buf), nil
		}

		if f.Node.Data == nil {
			return 0, nil
		}
		if f.Offset >= int64(len(f.Node.Data)) {
			return 0, nil
		}
		n := copy(buf, f.Node.Data[f.Offset:])
		f.Offset += int64(n)
		return n, nil
	}

	return 0, nil
}

// Pread reads from fd at the given offset without changing the file position.
func (v *VFS) Pread(fd int, buf []byte, offset int64) (int, error) {
	v.mu.Lock()
	f, ok := v.fds[fd]
	if !ok {
		v.mu.Unlock()
		return -1, fmt.Errorf("bad fd %d", fd)
	}
	v.mu.Unlock()

	// Host file pread
	if f.HostFile != nil {
		return f.HostFile.ReadAt(buf, offset)
	}

	if f.Node.Name == "urandom" {
		rand.Read(buf)
		return len(buf), nil
	}

	if f.Node.Name == "zero" {
		for i := range buf {
			buf[i] = 0
		}
		return len(buf), nil
	}

	// VFS regular file
	if f.Node != nil && f.Node.Data != nil {
		if offset >= int64(len(f.Node.Data)) {
			return 0, nil
		}
		n := copy(buf, f.Node.Data[offset:])
		return n, nil
	}

	return 0, nil
}

// Pwrite writes to fd at the given offset without changing the file position.
func (v *VFS) Pwrite(fd int, data []byte, offset int64) (int, error) {
	v.mu.Lock()
	f, ok := v.fds[fd]
	if !ok {
		v.mu.Unlock()
		return -1, fmt.Errorf("bad fd %d", fd)
	}

	// Host file pwrite
	if f.HostFile != nil {
		hostFile := f.HostFile
		v.mu.Unlock()
		return hostFile.WriteAt(data, offset)
	}

	// VFS regular file
	if f.Node != nil {
		end := offset + int64(len(data))
		if end > int64(len(f.Node.Data)) {
			f.Node.Data = append(f.Node.Data, make([]byte, end-int64(len(f.Node.Data)))...)
		}
		copy(f.Node.Data[offset:], data)
		f.Node.Size = int64(len(f.Node.Data))
		f.Node.Mtime = time.Now()
		v.mu.Unlock()
		return len(data), nil
	}

	v.mu.Unlock()
	return -1, fmt.Errorf("cannot pwrite to fd %d", fd)
}

// Write writes data to fd. For fd 1/2, routes to host output.
func (v *VFS) Write(fd int, data []byte) (int, error) {
	v.mu.Lock()
	f, ok := v.fds[fd]
	if !ok {
		v.mu.Unlock()
		return -1, fmt.Errorf("bad fd %d", fd)
	}

	if (fd == 1 || fd == 2) && v.HostOut != nil {
		v.mu.Unlock()
		v.HostOut(fd, data)
		return len(data), nil
	}

	// EventFD write
	if f.EventFD != nil {
		v.mu.Unlock()
		return f.EventFD.Write(data)
	}

	// Socket write
	if f.Socket != nil {
		v.mu.Unlock()
		return f.Socket.Write(data)
	}

	// Host file write (memfd etc.)
	if f.HostFile != nil {
		v.mu.Unlock()
		return f.HostFile.Write(data)
	}

	// Pipe write end
	if f.PipeW != nil {
		v.mu.Unlock()
		return f.PipeW.Write(data)
	}

	// /dev/null
	if f.Node != nil && f.Node.Name == "null" {
		v.mu.Unlock()
		return len(data), nil
	}

	// Regular file write
	if f.Node != nil {
		if f.Flags&O_APPEND != 0 {
			f.Offset = int64(len(f.Node.Data))
		}
		end := f.Offset + int64(len(data))
		if end > int64(len(f.Node.Data)) {
			f.Node.Data = append(f.Node.Data, make([]byte, end-int64(len(f.Node.Data)))...)
		}
		copy(f.Node.Data[f.Offset:], data)
		f.Offset = end
		f.Node.Size = int64(len(f.Node.Data))
		f.Node.Mtime = time.Now()
		v.mu.Unlock()
		return len(data), nil
	}

	v.mu.Unlock()
	return -1, fmt.Errorf("cannot write to fd %d", fd)
}

// Close closes a file descriptor.
func (v *VFS) Close(fd int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return fmt.Errorf("bad fd %d", fd)
	}
	if f.PipeR != nil {
		f.PipeR.Close()
	}
	if f.PipeW != nil {
		f.PipeW.Close()
	}
	if f.Socket != nil {
		f.Socket.Close()
	}
	if f.EventFD != nil {
		f.EventFD.Close()
	}
	if f.HostFile != nil {
		f.HostFile.Close()
	}
	delete(v.fds, fd)
	return nil
}

// Dup duplicates a file descriptor to the lowest available fd.
func (v *VFS) Dup(oldfd int) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[oldfd]
	if !ok {
		return -1, fmt.Errorf("bad fd %d", oldfd)
	}
	newfd := v.nextFD
	v.nextFD++
	newFD := &FD{
		Node:   f.Node,
		Offset: f.Offset,
		Flags:  f.Flags,
		PipeR:  f.PipeR,
		PipeW:  f.PipeW,
	}
	// Duplicate host-backed resources so each guest FD has its own host FD.
	if f.HostFile != nil {
		dupFD, err := syscall.Dup(int(f.HostFile.Fd()))
		if err != nil {
			return -1, err
		}
		newFD.HostFile = os.NewFile(uintptr(dupFD), f.HostFile.Name())
	} else if f.Socket != nil {
		hfd := f.Socket.HostFD()
		if hfd >= 0 {
			dupFD, err := syscall.Dup(hfd)
			if err != nil {
				return -1, err
			}
			newFD.HostFile = os.NewFile(uintptr(dupFD), "dup-socket")
		}
	}
	v.fds[newfd] = newFD
	return newfd, nil
}

// Dup3 duplicates oldfd to newfd (closing newfd first if open).
func (v *VFS) Dup3(oldfd, newfd int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[oldfd]
	if !ok {
		return fmt.Errorf("bad fd %d", oldfd)
	}
	if _, ok := v.fds[newfd]; ok {
		delete(v.fds, newfd)
	}
	newFD := &FD{
		Node:   f.Node,
		Offset: f.Offset,
		Flags:  f.Flags,
		PipeR:  f.PipeR,
		PipeW:  f.PipeW,
	}
	// Duplicate host-backed resources so each guest FD has its own host FD.
	if f.HostFile != nil {
		dupFD, err := syscall.Dup(int(f.HostFile.Fd()))
		if err != nil {
			return err
		}
		newFD.HostFile = os.NewFile(uintptr(dupFD), f.HostFile.Name())
	} else if f.Socket != nil {
		hfd := f.Socket.HostFD()
		if hfd >= 0 {
			dupFD, err := syscall.Dup(hfd)
			if err != nil {
				return err
			}
			newFD.HostFile = os.NewFile(uintptr(dupFD), "dup-socket")
		}
	}
	v.fds[newfd] = newFD
	if newfd >= v.nextFD {
		v.nextFD = newfd + 1
	}
	return nil
}

// Lseek changes the offset of fd.
func (v *VFS) Lseek(fd int, offset int64, whence int) (int64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return -1, fmt.Errorf("bad fd %d", fd)
	}
	// Host files: delegate to real lseek
	if f.Node == nil {
		if f.HostFile != nil {
			off, err := f.HostFile.Seek(offset, whence)
			if err != nil {
				return -1, err
			}
			f.Offset = off
			return off, nil
		}
		return -1, fmt.Errorf("bad fd (no host file)")
	}
	// Character devices can't seek
	if f.Node.FileMode&S_IFMT == S_IFCHR {
		return -1, fmt.Errorf("ESPIPE")
	}
	switch whence {
	case SEEK_SET:
		f.Offset = offset
	case SEEK_CUR:
		f.Offset += offset
	case SEEK_END:
		f.Offset = int64(len(f.Node.Data)) + offset
	default:
		return -1, fmt.Errorf("invalid whence %d", whence)
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	return f.Offset, nil
}

// Pipe2 creates a pipe, returning (readFD, writeFD).
func (v *VFS) Pipe2(flags int) (int, int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	shared := &PipeEnd{}
	rfd := v.nextFD
	v.nextFD++
	wfd := v.nextFD
	v.nextFD++
	v.fds[rfd] = &FD{
		Node:  &VNode{Name: "pipe", FileMode: S_IFIFO | 0600, Ino: nextInode()},
		PipeR: shared,
	}
	v.fds[wfd] = &FD{
		Node:  &VNode{Name: "pipe", FileMode: S_IFIFO | 0600, Ino: nextInode()},
		PipeW: shared,
	}
	return rfd, wfd, nil
}

// Stat returns stat info for a VNode.
func (v *VFS) Stat(fd int) *VNode {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return nil
	}
	if f.HostFile != nil {
		if stat, err := f.HostFile.Stat(); err == nil {
			return hostStatToVNode(f.HostFile.Name(), stat)
		}
		return nil
	}
	return f.Node
}

// StatPath returns stat info for a path.
func (v *VFS) StatPath(dirfd int, path string) (*VNode, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	absPath := v.ResolvePath(dirfd, path)
	node, err := v.Resolve(absPath)
	if err == nil {
		return node, nil
	}
	if strings.HasPrefix(absPath, "/lib") || strings.HasPrefix(absPath, "/usr") || strings.HasPrefix(absPath, "/etc") ||
		strings.HasPrefix(absPath, "/run/") || strings.HasPrefix(absPath, "/home/") ||
		strings.HasPrefix(absPath, "/sys/") || strings.HasPrefix(absPath, "/proc/") {
		if stat, oerr := os.Stat(absPath); oerr == nil {
			return hostStatToVNode(absPath, stat), nil
		}
	}
	return nil, err
}

func hostStatToVNode(name string, stat os.FileInfo) *VNode {
	mode := stat.Mode()
	isDir := mode.IsDir()
	var fileMode uint32 = uint32(mode.Perm())
	if isDir {
		fileMode |= S_IFDIR
	} else if mode&os.ModeSymlink != 0 {
		fileMode |= S_IFLNK
	} else {
		fileMode |= S_IFREG
	}
	return &VNode{
		Name:     name,
		IsDir:    isDir,
		Size:     stat.Size(),
		FileMode: fileMode,
		Ino:      nextInode(),
		Nlink:    1,
		Uid:      1000,
		Gid:      1000,
		Atime:    stat.ModTime(),
		Mtime:    stat.ModTime(),
		Ctime:    stat.ModTime(),
	}
}

// Readlinkat reads a symlink. Handles /proc/self/exe specially.
func (v *VFS) Readlinkat(dirfd int, path string) (string, error) {
	absPath := v.ResolvePath(dirfd, path)
	if absPath == "/proc/self/exe" {
		if v.ElfPath != "" {
			return v.ElfPath, nil
		}
		return "/govm", nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	node, err := v.Resolve(absPath)
	if err != nil {
		if strings.HasPrefix(absPath, "/lib") || strings.HasPrefix(absPath, "/usr") || strings.HasPrefix(absPath, "/etc") {
			if target, oerr := os.Readlink(absPath); oerr == nil {
				return target, nil
			}
		}
		return "", err
	}
	if node.LinkTarget != "" {
		return node.LinkTarget, nil
	}
	return "", fmt.Errorf("not a symlink: %s", absPath)
}

// Getcwd returns the current working directory.
func (v *VFS) Getcwd() string {
	return v.Cwd
}

// GetFD returns the FD struct for a file descriptor (for external inspection).
func (v *VFS) GetFD(fd int) *FD {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.fds[fd]
}

// Getdents64 returns directory entries for a directory fd.
func (v *VFS) Getdents64(fd int) []*VNode {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return nil
	}
	if f.Node == nil || !f.Node.IsDir {
		return nil
	}
	start := int(f.Offset)
	if start >= len(f.Node.Children) {
		return nil // EOF - all entries already returned
	}
	var entries []*VNode
	i := 0
	for _, child := range f.Node.Children {
		if i >= start {
			entries = append(entries, child)
		}
		i++
	}
	f.Offset = int64(i)
	return entries
}

// ResolvePath resolves a path relative to dirfd.
func (v *VFS) ResolvePath(dirfd int, path string) string {
	if len(path) > 0 && path[0] == '/' {
		return path
	}
	if dirfd == -100 { // AT_FDCWD
		if v.Cwd == "/" {
			return "/" + path
		}
		return v.Cwd + "/" + path
	}
	// Use the directory fd's path
	return "/" + path
}

// Resolve walks the VFS tree to find a node by path.
func (v *VFS) Resolve(path string) (*VNode, error) {
	if path == "/" || path == "" {
		return v.root, nil
	}
	parts := SplitAll(path)
	cur := v.root
	for _, p := range parts {
		if p == "." {
			continue
		}
		if p == ".." {
			// Can't go above root
			continue
		}
		if !cur.IsDir {
			return nil, fmt.Errorf("not a directory: %s", p)
		}
		child, ok := cur.Children[p]
		if !ok {
			// Case-insensitive fallback (Windows filenames are case-insensitive)
			lp := strings.ToLower(p)
			for name, node := range cur.Children {
				if strings.ToLower(name) == lp {
					child = node
					ok = true
					break
				}
			}
			if !ok {
				return nil, fmt.Errorf("not found: %s", path)
			}
		}
		cur = child
	}
	return cur, nil
}

func SplitPath(path string) (string, string) {
	// Remove trailing slashes
	path = strings.TrimRight(path, "/")
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			dir := path[:i]
			if dir == "" {
				dir = "/"
			}
			return dir, path[i+1:]
		}
	}
	return "/", path
}

// Lock locks the VFS mutex externally (for multi-step operations).
func (v *VFS) Lock() {
	v.mu.Lock()
}

// Unlock unlocks the VFS mutex.
func (v *VFS) Unlock() {
	v.mu.Unlock()
}

// --- Socket operations ---

// AllocSocket creates a guest FD backed by a SocketFD.
func (v *VFS) AllocSocket(domain, sockType int) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	sock := NewSocketFD(domain, sockType)
	fd := v.nextFD
	v.nextFD++
	v.fds[fd] = &FD{Socket: sock}
	return fd, nil
}

// AllocSocketUnlocked creates a guest FD from an existing SocketFD.
// Caller must hold v.mu.
func (v *VFS) AllocSocketUnlocked(sock *SocketFD) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	fd := v.nextFD
	v.nextFD++
	v.fds[fd] = &FD{Socket: sock}
	return fd
}

// ConnectSocket connects a socket FD to a host path.
func (v *VFS) ConnectSocket(fd int, path string) error {
	v.mu.Lock()
	f, ok := v.fds[fd]
	v.mu.Unlock()
	if !ok || f.Socket == nil {
		return fmt.Errorf("not a socket fd %d", fd)
	}
	return f.Socket.Connect(path)
}

// GetSocket returns the SocketFD for a guest FD, or nil.
func (v *VFS) GetSocket(fd int) *SocketFD {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return nil
	}
	return f.Socket
}

// --- Host file (memfd) operations ---

// AllocHostFile creates a guest FD backed by a real host os.File.
func (v *VFS) AllocHostFile(f *os.File) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	fd := v.nextFD
	v.nextFD++
	node := newVNode(f.Name(), false)
	node.FileMode = S_IFREG | 0600
	v.fds[fd] = &FD{Node: node, HostFile: f}
	return fd
}

// GetHostFile returns the host os.File for a guest FD, or nil.
func (v *VFS) GetHostFile(fd int) *os.File {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return nil
	}
	return f.HostFile
}

// GetHostFDNum returns the real host FD number for a guest FD.
// Returns -1 if the guest FD is not backed by a host resource.
func (v *VFS) GetHostFDNum(guestFD int) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[guestFD]
	if !ok {
		return -1
	}
	if f.HostFile != nil {
		return int(f.HostFile.Fd())
	}
	if f.Socket != nil {
		return f.Socket.HostFD()
	}
	return -1
}

// WrapHostFD wraps a received real host FD number into a new guest FD.
func (v *VFS) WrapHostFD(hostFDnum int, name string) int {
	v.mu.Lock()
	defer v.mu.Unlock()
	hostFile := os.NewFile(uintptr(hostFDnum), name)
	node := newVNode(name, false)
	node.FileMode = S_IFREG | 0600
	fd := v.nextFD
	v.nextFD++
	v.fds[fd] = &FD{Node: node, HostFile: hostFile}
	return fd
}

// Unlinkat removes a file or empty directory from the VFS.
func (v *VFS) Unlinkat(dirfd int, path string, flags int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	absPath := v.ResolvePath(dirfd, path)
	dir, name := SplitPath(absPath)
	parent, err := v.Resolve(dir)
	if err != nil {
		return err
	}
	child, ok := parent.Children[name]
	if !ok {
		return fmt.Errorf("not found: %s", absPath)
	}
	// AT_REMOVEDIR = 0x200
	if flags&0x200 != 0 {
		if !child.IsDir {
			return fmt.Errorf("not a directory")
		}
		if len(child.Children) > 0 {
			return fmt.Errorf("directory not empty")
		}
	} else {
		if child.IsDir {
			return fmt.Errorf("is a directory")
		}
	}
	delete(parent.Children, name)
	return nil
}

// RemoveAll removes a file or directory tree from the VFS.
func (v *VFS) RemoveAll(dirfd int, path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	absPath := v.ResolvePath(dirfd, path)
	if absPath == "/" {
		return fmt.Errorf("cannot remove VFS root")
	}
	dir, name := SplitPath(absPath)
	parent, err := v.Resolve(dir)
	if err != nil {
		return nil
	}
	actualName, _, ok := findChildFold(parent, name)
	if !ok {
		return nil
	}
	delete(parent.Children, actualName)
	return nil
}

// Renameat renames a file or directory in the VFS.
func (v *VFS) Renameat(olddirfd int, oldpath string, newdirfd int, newpath string) error {
	return v.RenameatWithCommit(olddirfd, oldpath, newdirfd, newpath, RenameOptions{ReplaceExisting: true}, nil)
}

// RenameatWithCommit runs a non-VFS callback while holding the VFS lock.
// The callback must not call back into this VFS.
func (v *VFS) RenameatWithCommit(olddirfd int, oldpath string, newdirfd int, newpath string, options RenameOptions, commit func(source RenameCommitSource) (RenameCommitResult, error)) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	absOld := v.ResolvePath(olddirfd, oldpath)
	absNew := v.ResolvePath(newdirfd, newpath)

	newDir, newName := SplitPath(absNew)

	oldParent, oldName, node, err := v.resolveParentEntry(absOld)
	if err != nil {
		return err
	}

	newParent, err := v.Resolve(newDir)
	if err != nil || !newParent.IsDir {
		return fmt.Errorf("%w: %s", ErrRenameParentNotFound, absNew)
	}
	if node.IsDir && vnodeContains(node, newParent) {
		return ErrInvalidPathAlias
	}
	dstName, dstNode, dstExists := findChildFold(newParent, newName)
	sameEntry := oldParent == newParent && dstExists && dstNode == node
	if dstExists && !sameEntry {
		if options.RejectExistingDirectory && dstNode.IsDir {
			return fmt.Errorf("destination is a directory: %s", absNew)
		}
		if node.IsDir != dstNode.IsDir {
			return fmt.Errorf("source and destination types differ")
		}
		if dstNode.IsDir && len(dstNode.Children) != 0 {
			return fmt.Errorf("destination directory is not empty")
		}
		if !options.ReplaceExisting {
			return fmt.Errorf("%w: %s", os.ErrExist, absNew)
		}
	}

	var commitResult RenameCommitResult
	if commit != nil {
		commitResult, err = commit(RenameCommitSource{
			Data:  append([]byte(nil), node.Data...),
			IsDir: node.IsDir,
		})
		if err != nil {
			return err
		}
	}

	if commitResult.KeepSource {
		if node.IsDir {
			return fmt.Errorf("cannot retain a directory during rename")
		}
		if sameEntry {
			return ErrInvalidPathAlias
		}
		if dstExists {
			delete(newParent.Children, dstName)
		}
		copied := *node
		copied.Name = newName
		copied.Data = append([]byte(nil), node.Data...)
		copied.Children = make(map[string]*VNode)
		copied.Ino = nextInode()
		copied.Nlink = 1
		newParent.Children[newName] = &copied
		return nil
	}

	delete(oldParent.Children, oldName)
	if dstExists && !sameEntry {
		delete(newParent.Children, dstName)
	}
	node.Name = newName
	newParent.Children[newName] = node
	return nil
}

func vnodeContains(root, target *VNode) bool {
	if root == target {
		return true
	}
	if !root.IsDir {
		return false
	}
	for _, child := range root.Children {
		if vnodeContains(child, target) {
			return true
		}
	}
	return false
}

// ReplaceFile atomically replaces one VFS directory entry with another.
func (v *VFS) ReplaceFile(replacedPath, replacementPath, backupPath string) error {
	return v.ReplaceFileWithCommit(replacedPath, replacementPath, backupPath, nil)
}

// ReplaceFileWithCommit runs an external commit before changing VFS entries.
func (v *VFS) ReplaceFileWithCommit(replacedPath, replacementPath, backupPath string, commit func(replacedData, replacementData []byte) error) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	replacedPath = pathClean(v.ResolvePath(-1, replacedPath))
	replacementPath = pathClean(v.ResolvePath(-1, replacementPath))
	backupPath = pathCleanOptional(v.ResolvePath(-1, backupPath), backupPath != "")
	if strings.EqualFold(replacedPath, replacementPath) ||
		(backupPath != "" && (strings.EqualFold(backupPath, replacedPath) || strings.EqualFold(backupPath, replacementPath))) {
		return ErrInvalidPathAlias
	}

	replacedParent, replacedName, replaced, err := v.resolveParentEntry(replacedPath)
	if err != nil || replaced.IsDir {
		return fmt.Errorf("replaced file is unavailable")
	}
	replacementParent, replacementName, replacement, err := v.resolveParentEntry(replacementPath)
	if err != nil || replacement.IsDir {
		return fmt.Errorf("replacement file is unavailable")
	}

	var backupParent *VNode
	var backupName string
	if backupPath != "" {
		backupDir, requestedName := SplitPath(backupPath)
		backupParent, err = v.Resolve(backupDir)
		if err != nil || !backupParent.IsDir {
			return fmt.Errorf("backup directory is unavailable")
		}
		backupName = requestedName
		if actualName, existing, ok := findChildFold(backupParent, requestedName); ok {
			if existing.IsDir {
				return fmt.Errorf("backup path is a directory")
			}
			backupName = actualName
		}
	}
	if commit != nil {
		replacedData := append([]byte(nil), replaced.Data...)
		replacementData := append([]byte(nil), replacement.Data...)
		if err := commit(replacedData, replacementData); err != nil {
			return err
		}
	}

	delete(replacementParent.Children, replacementName)
	delete(replacedParent.Children, replacedName)
	if backupPath != "" {
		delete(backupParent.Children, backupName)
		replaced.Name = backupName
		backupParent.Children[backupName] = replaced
	} else {
		replaced.Nlink = 0
	}
	replacement.Mode = replaced.Mode
	replacement.FileMode = replaced.FileMode
	replacement.Uid = replaced.Uid
	replacement.Gid = replaced.Gid
	replacement.Ctime = replaced.Ctime
	replacement.Name = replacedName
	replacedParent.Children[replacedName] = replacement
	return nil
}

func (v *VFS) resolveParentEntry(filePath string) (*VNode, string, *VNode, error) {
	dir, requestedName := SplitPath(filePath)
	parent, err := v.Resolve(dir)
	if err != nil || !parent.IsDir {
		return nil, "", nil, fmt.Errorf("parent directory is unavailable")
	}
	actualName, node, ok := findChildFold(parent, requestedName)
	if !ok {
		return nil, "", nil, fmt.Errorf("not found: %s", filePath)
	}
	return parent, actualName, node, nil
}

func findChildFold(parent *VNode, requestedName string) (string, *VNode, bool) {
	if child, ok := parent.Children[requestedName]; ok {
		return requestedName, child, true
	}
	for name, child := range parent.Children {
		if strings.EqualFold(name, requestedName) {
			return name, child, true
		}
	}
	return "", nil, false
}

func pathClean(filePath string) string {
	parts := SplitAll(filePath)
	return "/" + strings.Join(parts, "/")
}

func pathCleanOptional(filePath string, present bool) string {
	if !present {
		return ""
	}
	return pathClean(filePath)
}

// Ftruncate truncates a file to the given length.
func (v *VFS) Ftruncate(fd int, length int64) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	f, ok := v.fds[fd]
	if !ok {
		return fmt.Errorf("bad fd %d", fd)
	}
	if f.Node.IsDir {
		return fmt.Errorf("is a directory")
	}
	if length < int64(len(f.Node.Data)) {
		f.Node.Data = f.Node.Data[:length]
	} else if length > int64(len(f.Node.Data)) {
		f.Node.Data = append(f.Node.Data, make([]byte, length-int64(len(f.Node.Data)))...)
	}
	f.Node.Size = length
	f.Node.Mtime = time.Now()
	return nil
}

// Chdir changes the current working directory.
func (v *VFS) Chdir(path string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	absPath := v.ResolvePath(-100, path)
	node, err := v.Resolve(absPath)
	if err != nil {
		return err
	}
	if !node.IsDir {
		return fmt.Errorf("not a directory: %s", absPath)
	}
	v.Cwd = absPath
	return nil
}

// Symlinkat creates a symlink.
func (v *VFS) Symlinkat(target string, dirfd int, linkpath string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	absPath := v.ResolvePath(dirfd, linkpath)
	dir, name := SplitPath(absPath)
	parent, err := v.Resolve(dir)
	if err != nil {
		return err
	}
	nd := newVNode(name, false)
	nd.FileMode = S_IFLNK | 0777
	nd.LinkTarget = target
	parent.Children[name] = nd
	return nil
}

func SplitAll(path string) []string {
	var parts []string
	for _, p := range strings.Split(path, "/") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

// FDSnapshot is a shallow copy of the FD table used for vfork/posix_spawn.
type FDSnapshot struct {
	fds    map[int]*FD
	nextFD int
}

// SnapshotFDs returns a shallow copy of the current FD table.
// Used before a vfork child goroutine runs so we can restore the parent's
// FD table after the child calls execve (which modifies the shared table
// via dup2/close file actions).
func (v *VFS) SnapshotFDs() FDSnapshot {
	v.mu.Lock()
	defer v.mu.Unlock()
	snap := FDSnapshot{
		fds:    make(map[int]*FD, len(v.fds)),
		nextFD: v.nextFD,
	}
	for k, fd := range v.fds {
		snap.fds[k] = fd
	}
	return snap
}

// RestoreFDs replaces the FD table with a previously-saved snapshot.
// Called after the vfork-child's execve to undo any dup2/close modifications
// that the child made to the shared FD table.
func (v *VFS) RestoreFDs(snap FDSnapshot) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fds = snap.fds
	v.nextFD = snap.nextFD
}
